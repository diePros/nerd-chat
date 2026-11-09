#!/usr/bin/env bash
# Installs the Sine Loco onion mirror on a fresh Debian 12 (or Ubuntu) machine or LXC container.
#   sudo ./install.sh [path to site/public]
#   SINGLE_HOP=0 sudo ./install.sh     # standard onion service (hides the server's location, slower)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -f /etc/debian_version ] || { echo "Debian or Ubuntu only"; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "${1:-$here/../public}" && pwd)
SINGLE_HOP=${SINGLE_HOP:-1}
ROOT=/srv/sineloco
LIB=/usr/local/lib/sineloco-mirror
[ -f "$SRC/index.html" ] || { echo "no index.html in $SRC"; exit 1; }

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends tor nginx curl jq gnupg ca-certificates

echo "== user and folders"
id sineloco-mirror >/dev/null 2>&1 || useradd --system --home-dir "$ROOT" --shell /usr/sbin/nologin sineloco-mirror
install -d -m 755 -o sineloco-mirror "$ROOT" "$ROOT/dl" "$ROOT/data" "$ROOT/data/downloads"
install -d -m 755 "$ROOT/builds" "$LIB" /etc/sineloco-mirror
install -m 755 "$here/sync-releases.sh" "$here/deploy-site.sh" "$LIB/"
if [ ! -f /etc/sineloco-mirror.conf ]; then
  cat > /etc/sineloco-mirror.conf <<'CONF'
# Which GitHub repository to mirror. Change after the repository rename.
REPO=diePros/nerd-chat
# How many of the newest releases to keep.
KEEP=3
# Optional: a read-only token (no scopes) lifts GitHub's anonymous rate limit.
#GITHUB_TOKEN=
# Optional: save the release signer's public key as /etc/sineloco-mirror/signing.asc and the mirror
# will verify SHA256SUMS.asc. To also pin the exact key, put its full fingerprint here.
#SIGNER_FPR=
CONF
  chmod 640 /etc/sineloco-mirror.conf; chgrp sineloco-mirror /etc/sineloco-mirror.conf
fi

echo "== website"
ROOT=$ROOT "$LIB/deploy-site.sh" "$SRC"

echo "== nginx"
rm -f /etc/nginx/sites-enabled/default       # the stock site listens on every interface
install -d /etc/nginx/snippets
install -m 644 "$here/nginx/sineloco-headers.conf" /etc/nginx/snippets/
install -m 644 "$here/nginx/sineloco.conf" /etc/nginx/conf.d/
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "== tor onion service"
pow=""
if tor --list-torrc-options 2>/dev/null | grep -qi '^HiddenServicePoWDefensesEnabled'; then
  pow="HiddenServicePoWDefensesEnabled 1"
else
  echo "   (this tor is too old for proof-of-work defences; skipped)"
fi
single=""
[ "$SINGLE_HOP" = 1 ] && single=$'HiddenServiceNonAnonymousMode 1\nHiddenServiceSingleHopMode 1\nSocksPort 0'
sed -e "s|@@SINGLE_HOP@@|$(printf '%s' "$single" | sed ':a;N;$!ba;s/\n/\\n/g')|" -e "s|@@POW@@|$pow|" \
  "$here/torrc.sineloco" > /etc/tor/sineloco.torrc
grep -q '^%include /etc/tor/sineloco.torrc' /etc/tor/torrc || echo '%include /etc/tor/sineloco.torrc' >> /etc/tor/torrc
systemctl enable tor@default >/dev/null 2>&1 || systemctl enable tor >/dev/null 2>&1 || true
systemctl restart tor@default 2>/dev/null || systemctl restart tor
for _ in $(seq 1 60); do [ -s /var/lib/tor/sineloco/hostname ] && break; sleep 1; done
[ -s /var/lib/tor/sineloco/hostname ] || { echo "tor did not create the onion address; see: journalctl -u tor@default"; exit 1; }

echo "== release sync"
install -m 644 "$here/systemd/sineloco-mirror-sync.service" "$here/systemd/sineloco-mirror-sync.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sineloco-mirror-sync.timer
systemctl start sineloco-mirror-sync.service || echo "   first sync failed; see: journalctl -u sineloco-mirror-sync"

echo
echo "Onion address:  http://$(cat /var/lib/tor/sineloco/hostname)/"
echo "Back up /var/lib/tor/sineloco/ (the secret key IS the address). Anyone with it can impersonate the site."
if [ "$SINGLE_HOP" = 1 ]; then
  echo
  echo "Single-hop mode: relays can see this machine's public IP. It must be your VPN's address:"
  echo "   Public IP seen from here: $(curl -fsS --max-time 15 https://check.torproject.org/api/ip 2>/dev/null | jq -r '.IP // "unknown"')"
  echo "If that is your home IP, STOP: fix the VPN/kill switch before sharing the address."
fi
