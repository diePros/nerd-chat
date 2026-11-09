#!/usr/bin/env bash
# WireGuard + kill switch for the onion mirror.
#   vpn-setup.sh --print-rules <wg0.conf>   print the firewall rules (no changes; for checking)
#   sudo vpn-setup.sh --install <wg0.conf>  install the config, firewall, and bring the tunnel up
# Fails closed: the firewall drops everything that is not inside the tunnel (or the tunnel's own
# handshake packets), so if the VPN is down or misconfigured the server simply has no network.
set -euo pipefail

mode=${1:?usage: $0 --print-rules|--install <wg0.conf>}
src=${2:?path to your WireGuard config}
[ -r "$src" ] || { echo "cannot read $src"; exit 1; }
IF=wg0

grep -qi '^[[:space:]]*PrivateKey' "$src" || { echo "$src has no PrivateKey line; is it a WireGuard config?"; exit 1; }
grep -Eqi '^[[:space:]]*AllowedIPs[[:space:]]*=.*0\.0\.0\.0/0' "$src" ||
  { echo "AllowedIPs must include 0.0.0.0/0 (all traffic through the tunnel). Use your VPN's full-tunnel config."; exit 1; }

# Endpoint lines: host:port or [v6]:port
mapfile -t endpoints < <(sed -nE 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*([^[:space:]#]+).*/\1/Ip' "$src")
[ "${#endpoints[@]}" -gt 0 ] || { echo "no Endpoint in $src"; exit 1; }

declare -a v4_rules=() v6_rules=() rewrites=()
for ep in "${endpoints[@]}"; do
  port=${ep##*:}; host=${ep%:*}; host=${host#[}; host=${host%]}
  [[ $port =~ ^[0-9]+$ ]] || { echo "bad endpoint $ep"; exit 1; }
  if [[ $host =~ ^[0-9.]+$ ]]; then ips=("$host")
  elif [[ $host == *:* ]]; then ips=("$host")
  else
    # a hostname: resolve it now, because the firewall must name exact addresses
    mapfile -t ips < <(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)
    [ "${#ips[@]}" -gt 0 ] || mapfile -t ips < <(getent ahostsv6 "$host" | awk '{print $1}' | sort -u)
    [ "${#ips[@]}" -gt 0 ] || { echo "cannot resolve $host"; exit 1; }
    rewrites+=("$host|${ips[0]}")
  fi
  for ip in "${ips[@]}"; do
    if [[ $ip == *:* ]]; then v6_rules+=("ip6 daddr $ip udp dport $port accept")
    else v4_rules+=("ip daddr $ip udp dport $port accept"); fi
  done
done

rules() {
cat <<NFT
#!/usr/sbin/nft -f
# Kill switch written by sineloco vpn-setup.sh. Do not edit by hand; rerun the installer instead.
flush ruleset
# Private (LAN) address ranges. They never route to the internet, so talking to them cannot leak.
define lan4 = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
define lan6 = { fc00::/7, fe80::/10 }
table inet killswitch {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    # SSH, from the local network only (nothing listens unless you install sshd). Matched by port, not by
    # connection state: a session that was already open when these rules loaded looks "new" to the tracker.
    ip saddr \$lan4 tcp dport 22 accept
    ip6 saddr \$lan6 tcp dport 22 accept
    # LAN plumbing that does not leave the LAN
    udp sport 67 udp dport 68 accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "$IF" accept
    # SSH replies to the local network (private ranges only, so never the internet)
    ip daddr \$lan4 tcp sport 22 accept
    ip6 daddr \$lan6 tcp sport 22 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept
    # only the VPN's own handshake and carrier packets may leave outside the tunnel
$(printf '    %s\n' "${v4_rules[@]:-}" "${v6_rules[@]:-}" | grep -v '^[[:space:]]*$')
  }
}
NFT
}

if [ "$mode" = "--print-rules" ]; then
  rules
  for r in "${rewrites[@]:-}"; do [ -n "$r" ] && echo "# note: Endpoint host ${r%%|*} will be pinned to ${r##*|}" >&2; done
  exit 0
fi
[ "$mode" = "--install" ] || { echo "unknown mode $mode"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

diagnose() { # prints what is needed to tell DNS, routing and firewall problems apart
  echo "--- diagnostics (safe to paste: no private key is shown)"
  echo "[wg]";        wg show "$IF" 2>&1 | grep -v -i 'preshared' | head -12
  echo "[rules]";     ip rule 2>&1 | head -8
  echo "[routes]";    ip route show table all 2>&1 | grep -v -E '^(broadcast|local|fe80|ff00)' | head -12
  echo "[resolv.conf]"; cat /etc/resolv.conf 2>&1 | head -6
  if getent hosts check.torproject.org >/dev/null 2>&1; then echo "[DNS] name lookup works"; else echo "[DNS] name lookup FAILS"; fi
  if curl -fsS --max-time 8 -o /dev/null https://1.1.1.1/cdn-cgi/trace 2>/dev/null; then echo "[by IP] reaching 1.1.1.1 works"; else echo "[by IP] reaching 1.1.1.1 FAILS"; fi
  echo "--- end diagnostics"
}
egress_ip() { # prints the public IP as seen from the internet. Several sources, retried, validated.
  local v try
  for try in 1 2 3; do
    v=$(curl -fsS --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p')
    [[ $v =~ ^[0-9a-fA-F.:]+$ ]] && { echo "$v"; return 0; }
    v=$(curl -fsS --max-time 8 https://check.torproject.org/api/ip 2>/dev/null | jq -r '.IP // empty' 2>/dev/null)
    [[ $v =~ ^[0-9a-fA-F.:]+$ ]] && { echo "$v"; return 0; }
    v=$(curl -fsS --max-time 8 https://icanhazip.com 2>/dev/null | tr -d '[:space:]')
    [[ $v =~ ^[0-9a-fA-F.:]+$ ]] && { echo "$v"; return 0; }
    sleep 2
  done
  return 1
}

# Does this host let the container make WireGuard interfaces? (needs the kernel module on the Proxmox host)
if ! ip link add dev wgprobe type wireguard 2>/dev/null; then
  echo "This container cannot create a WireGuard interface."
  echo "On the Proxmox HOST run: modprobe wireguard   (and make it permanent: echo wireguard >> /etc/modules)"
  exit 1
fi
ip link del wgprobe

before=$(egress_ip || true)
[ -n "$before" ] || echo "(could not read the current public IP; continuing)"

echo "== WireGuard config"
install -d -m 700 /etc/wireguard
if [ "$src" -ef "/etc/wireguard/$IF.conf" ]; then chmod 600 "/etc/wireguard/$IF.conf"   # already in place
else install -m 600 "$src" "/etc/wireguard/$IF.conf"; fi
pin_endpoints() { # $1 = file; replaces each resolved hostname by its IP
  local r h ip
  for r in "${rewrites[@]:-}"; do
    [ -n "$r" ] || continue
    h=${r%%|*}; ip=${r##*|}; [[ $ip == *:* ]] && ip="[$ip]"
    sed -i -E "s#^([[:space:]]*Endpoint[[:space:]]*=[[:space:]]*)${h//./\\.}(:[0-9]+)#\1${ip}\2#I" "$1"
    echo "   Endpoint host ${h} pinned to ${ip} (rerun the installer if your VPN changes that address)"
  done
}
pin_endpoints /etc/wireguard/$IF.conf
grep -Eqi '^[[:space:]]*DNS[[:space:]]*=' /etc/wireguard/$IF.conf && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openresolv >/dev/null

echo "== kill switch"
[ -f /etc/nftables.conf ] && [ ! -f /etc/nftables.conf.pre-sineloco ] && cp /etc/nftables.conf /etc/nftables.conf.pre-sineloco
rules > /etc/nftables.conf.new
nft -c -f /etc/nftables.conf.new                 # a syntax error stops here, before anything is applied
mv /etc/nftables.conf.new /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1
# Safety net against locking yourself out: if this script has not confirmed success within 3 minutes,
# the live rules are removed again. (Tor is not running yet at this point, so nothing is exposed;
# the rules in /etc/nftables.conf still load at boot.)
setsid sh -c 'sleep 180; nft delete table inet killswitch 2>/dev/null' >/dev/null 2>&1 &
watchdog=$!
nft -f /etc/nftables.conf

echo "== tunnel"
systemctl enable wg-quick@$IF >/dev/null 2>&1
systemctl restart wg-quick@$IF
for _ in $(seq 1 30); do
  [ "$(wg show $IF latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -n1)" -gt 0 ] 2>/dev/null && break
  sleep 1
done
hs=$(wg show $IF latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -n1 || true)
if [ -z "${hs:-}" ] || [ "$hs" = 0 ]; then
  echo "No handshake with the VPN. The kill switch is on, so nothing leaks; fix the config and rerun."
  echo "Check: journalctl -u wg-quick@$IF   and   wg show"
  diagnose; exit 1
fi
sleep 3
after=$(egress_ip || true)
echo "   public IP before: ${before:-unknown}"
echo "   public IP now:    ${after:-unknown}"
if [ -z "$after" ]; then echo "Cannot reach the internet through the tunnel."; diagnose; exit 1; fi
if [ -n "$before" ] && [ "$before" = "$after" ]; then
  echo "The public IP did not change, so traffic is NOT going through the VPN. Stopping."
  exit 1
fi
/usr/local/sbin/sineloco-vpn-check --quiet || { echo "The VPN check failed (see above). Stopping."; exit 1; }
kill "$watchdog" 2>/dev/null || true             # confirmed: keep the kill switch
echo "   leak test passed: nothing leaves outside the tunnel"
