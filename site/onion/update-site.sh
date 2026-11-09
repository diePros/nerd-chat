#!/usr/bin/env bash
# Keeps the onion website in step with the repository: fetches the newest commit of the site branch,
# deploys it ONLY if that commit carries a valid signature from your key, and does nothing otherwise.
# (This server serves Tor users: unsigned code from a branch must never go live by itself.)
set -euo pipefail
umask 022

CONF=${SINELOCO_MIRROR_CONF:-/etc/sineloco-mirror.conf}
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

REPO=${REPO:?set REPO in $CONF}
SITE_REPO_URL=${SITE_REPO_URL:-https://github.com/$REPO.git}
SITE_REF=${SITE_REF:-main}
SITE_GPG_KEY=${SITE_GPG_KEY:-/etc/sineloco-mirror/site-signing.asc}   # your public key (gpg --export --armor)
SITE_SIGNER_FPR=${SITE_SIGNER_FPR:-}        # optional: pin the exact key (primary or signing-subkey fingerprint)
SITE_ALLOW_UNSIGNED=${SITE_ALLOW_UNSIGNED:-0}
ROOT=${ROOT:-/srv/sineloco}
STATE=${STATE:-/var/lib/sineloco-site}
DEPLOY=${DEPLOY:-/usr/local/lib/sineloco-mirror/deploy-site.sh}
MAX_SITE_KB=${MAX_SITE_KB:-5120}

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
mkdir -p "$STATE"
exec 9>"$STATE/.lock"
flock -n 9 || { log "another update is running"; exit 0; }

if [ ! -r "$SITE_GPG_KEY" ] && [ "$SITE_ALLOW_UNSIGNED" != 1 ]; then
  log "automatic site updates are OFF: no signing key at $SITE_GPG_KEY (see site/onion/README.md)"
  exit 0
fi

tmp=$(mktemp -d); gh=$(mktemp -d); chmod 700 "$gh"
trap 'rm -rf "$tmp" "$gh"' EXIT

repo="$STATE/repo"
[ -d "$repo/.git" ] || { git init -q "$repo"; git -C "$repo" remote add origin "$SITE_REPO_URL"; }
git -C "$repo" remote set-url origin "$SITE_REPO_URL"
git -C "$repo" fetch -q --depth 1 --no-tags origin "$SITE_REF"
commit=$(git -C "$repo" rev-parse FETCH_HEAD)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { log "unexpected commit id"; exit 1; }

if [ "$(cat "$STATE/deployed" 2>/dev/null || true)" = "$commit" ]; then
  log "already deployed ${commit:0:12}"; exit 0
fi

# --- signature ---
sigstate=none
if [ -r "$SITE_GPG_KEY" ]; then
  GNUPGHOME=$gh gpg --batch --quiet --import "$SITE_GPG_KEY" 2>/dev/null
  out=$(GNUPGHOME=$gh git -C "$repo" verify-commit --raw "$commit" 2>&1 || true)
  if grep -q '^\[GNUPG:\] VALIDSIG ' <<<"$out"; then
    if [ -n "$SITE_SIGNER_FPR" ] && ! grep -q "^\[GNUPG:\] VALIDSIG .*${SITE_SIGNER_FPR}" <<<"$out"; then
      log "REFUSED ${commit:0:12}: valid signature, but not from the pinned key $SITE_SIGNER_FPR"; exit 1
    fi
    sigstate=verified
  else
    if [ "$SITE_ALLOW_UNSIGNED" != 1 ]; then
      log "REFUSED ${commit:0:12}: no valid signature from the installed key"; exit 1
    fi
  fi
elif [ "$SITE_ALLOW_UNSIGNED" != 1 ]; then
  exit 0
fi
[ "$sigstate" = verified ] || log "WARNING: deploying ${commit:0:12} WITHOUT a verified signature (SITE_ALLOW_UNSIGNED=1)"

# --- take only site/public, as plain files ---
git -C "$repo" archive "$commit" site/public | tar -x -C "$tmp" --no-same-owner --no-same-permissions
src="$tmp/site/public"
[ -f "$src/index.html" ] || { log "REFUSED: no site/public/index.html in ${commit:0:12}"; exit 1; }
[ -z "$(find "$src" ! -type f ! -type d -print -quit)" ] || { log "REFUSED: links or special files in site/public"; exit 1; }
[ "$(du -sk "$src" | cut -f1)" -le "$MAX_SITE_KB" ] || { log "REFUSED: site/public is larger than ${MAX_SITE_KB} KB"; exit 1; }

ROOT=$ROOT "$DEPLOY" "$src"
echo "$commit" > "$STATE/deployed"
log "site updated to ${commit:0:12} (signature: $sigstate)"
