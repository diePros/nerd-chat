#!/usr/bin/env bash
# Builds the onion variant of the site from site/public and switches to it atomically.
#   deploy-site.sh <path to site/public> [ROOT=/srv/sineloco]
set -euo pipefail
SRC=${1:?usage: deploy-site.sh <path to site/public>}
ROOT=${ROOT:-/srv/sineloco}
[ -f "$SRC/index.html" ] || { echo "no index.html in $SRC"; exit 1; }

build="$ROOT/builds/$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$build"
cp -a "$SRC/." "$build/"
rm -f "$build/_headers"          # headers are set by nginx on the onion

# the Download button goes to the local downloads page instead of GitHub
sed -i 's#https://github.com/diePros/nerd-chat/releases/latest#/downloads/#' "$build/index.html"

# precompress once so nginx serves gzip_static with no CPU per request
find "$build" -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' \) -exec gzip -9 -k -n {} +

chmod -R a+rX "$build"
ln -sfn "$build" "$ROOT/site.new" && mv -T "$ROOT/site.new" "$ROOT/site"
ls -1dt "$ROOT"/builds/*/ | tail -n +4 | xargs -r rm -rf   # keep the last 3
echo "deployed $build"
