#!/usr/bin/env bash
# Checks the VPN. Fails closed: anything it cannot positively confirm counts as a failure.
#   sineloco-vpn-check [--quiet]      exit 0 only if tunnel is up, kill switch is loaded, nothing leaks
IF=wg0
quiet=0; [ "${1:-}" = "--quiet" ] && quiet=1
fail=0
say() { [ "$quiet" = 1 ] || echo "$@"; }
bad() { echo "FAIL: $*"; fail=1; }

if ip link show "$IF" >/dev/null 2>&1; then
  hs=$(wg show "$IF" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -n1)
  if [ -n "$hs" ] && [ "$hs" -gt 0 ] 2>/dev/null; then say "tunnel: $IF is up, last handshake $(( $(date +%s) - hs )) s ago"
  else bad "tunnel $IF exists but has no handshake with the VPN"; fi
else
  bad "tunnel $IF does not exist (the VPN is not running)"
fi

if nft list table inet killswitch >/dev/null 2>&1; then say "kill switch: loaded"
else bad "kill switch is not loaded: traffic can leave outside the VPN"; fi

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
ip=$(egress_ip || true)
if [ -n "$ip" ]; then say "public IP: $ip   (must be your VPN's, not your home IP)"; else bad "no internet through the tunnel"; fi

# Leak test: try to reach the internet bound to each real network port. It must NOT work.
tested=0
for dev in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -v -E '^(lo|wg0)$'); do
  curl -s --max-time 6 --interface "$dev" -o /dev/null https://check.torproject.org/ 2>/dev/null
  rc=$?
  case $rc in
    0)  bad "LEAK: the internet is reachable through $dev outside the tunnel" ;;
    45) bad "could not run the leak test on $dev (cannot bind to it)" ;;
    *)  say "leak test: $dev is blocked (curl exit $rc)"; tested=1 ;;
  esac
done
[ "$tested" = 1 ] || bad "no network port was leak-tested"

[ "$fail" = 0 ] && say "OK" || echo "NOT SAFE: do not run Tor in single-hop mode until this passes."
exit "$fail"
