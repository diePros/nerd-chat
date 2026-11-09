#!/usr/bin/env bash
# Mirrors the newest GitHub releases for the onion site, verifying every file.
# Safe by construction: a release only goes live after ALL its files match SHA256SUMS
# (and the signature, when a key is installed). On any failure the old state keeps being served.
set -euo pipefail
umask 022

CONF=${SINELOCO_MIRROR_CONF:-/etc/sineloco-mirror.conf}
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

REPO=${REPO:?set REPO in $CONF, e.g. REPO=diePros/nerd-chat}
API=${API_BASE:-https://api.github.com}
DL_PREFIX=${DL_PREFIX:-https://github.com/}      # asset URLs must start with this
ROOT=${ROOT:-/srv/sineloco}
KEEP=${KEEP:-3}                                   # newest releases kept
MAX_ASSET_MB=${MAX_ASSET_MB:-100}
KEYFILE=${KEYFILE:-/etc/sineloco-mirror/signing.asc}   # optional public key of the release signer
SIGNER_FPR=${SIGNER_FPR:-}                        # optional: require this exact fingerprint
GITHUB_TOKEN=${GITHUB_TOKEN:-}

TAG_RE='^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
NAME_RE='^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
DATE_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$'

mkdir -p "$ROOT"/{dl,data/downloads}
exec 9>"$ROOT/data/.lock"
flock -n 9 || { echo "another sync is running"; exit 0; }

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
api() {
  local h=(-H "Accept: application/vnd.github+json" -H "User-Agent: sineloco-mirror")
  [ -z "$GITHUB_TOKEN" ] || h+=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -fsS --max-time 30 "${h[@]}" "$API/repos/$REPO$1"
}
tmpdirs=()
cleanup() { for d in "${tmpdirs[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done; }
trap cleanup EXIT

releases=$(api "/releases?per_page=10" | jq -c --argjson n "$KEEP" '[.[] | select(.draft==false)][0:$n]')
repo_json=$(api "")
stars=$(jq -r '.stargazers_count // 0' <<<"$repo_json")

verify_release() { # $1 = directory holding the downloaded files; prints signature state
  local d=$1 f n want got sig=none
  [ -f "$d/SHA256SUMS" ] || { log "no SHA256SUMS"; return 1; }
  for f in "$d"/*; do
    n=$(basename "$f")
    case $n in SHA256SUMS|SHA256SUMS.asc|META.json) continue ;; esac
    want=$(awk -v n="$n" '$2==n || $2=="*"n {print $1}' "$d/SHA256SUMS" | head -n1)
    [[ $want =~ ^[0-9a-f]{64}$ ]] || { log "$n is not listed in SHA256SUMS"; return 1; }
    got=$(sha256sum "$f" | cut -d' ' -f1)
    [ "$want" = "$got" ] || { log "$n: checksum mismatch"; return 1; }
  done
  if [ -f "$d/SHA256SUMS.asc" ]; then
    sig=unverified
    if [ -r "$KEYFILE" ]; then
      local gh out; gh=$(mktemp -d); tmpdirs+=("$gh"); chmod 700 "$gh"
      GNUPGHOME=$gh gpg --batch --quiet --import "$KEYFILE" 2>/dev/null
      out=$(GNUPGHOME=$gh gpg --batch --status-fd 1 --verify "$d/SHA256SUMS.asc" "$d/SHA256SUMS" 2>/dev/null || true)
      if grep -q '^\[GNUPG:\] VALIDSIG ' <<<"$out"; then
        if [ -n "$SIGNER_FPR" ] && ! grep -q "^\[GNUPG:\] VALIDSIG .*${SIGNER_FPR}" <<<"$out"; then
          log "signature is valid but not from $SIGNER_FPR"; return 1
        fi
        sig=verified
      else
        log "SHA256SUMS.asc does not verify"; return 1
      fi
    fi
  fi
  echo "$sig"
}

mirror_release() { # $1 = one release object (json)
  local r=$1 tag dest tmp
  tag=$(jq -r '.tag_name' <<<"$r")
  [[ $tag =~ $TAG_RE ]] || { log "skip odd tag"; return 0; }
  dest="$ROOT/dl/$tag"
  [ -f "$dest/META.json" ] && return 0
  tmp=$(mktemp -d "$ROOT/dl/.tmp.XXXXXX"); tmpdirs+=("$tmp")
  while IFS=$'\t' read -r name size url digest; do
    [[ $name =~ $NAME_RE ]] || { log "skip asset with odd name in $tag"; return 1; }
    [ "$size" -le $((MAX_ASSET_MB*1024*1024)) ] || { log "$name too large"; return 1; }
    case $url in "$DL_PREFIX"*) ;; *) log "$name: unexpected download host"; return 1 ;; esac
    curl -fsSL --max-time 600 --max-filesize $((MAX_ASSET_MB*1024*1024)) -o "$tmp/$name" "$url"
    if [[ $digest == sha256:* ]]; then   # GitHub's own digest, when it reports one
      [ "${digest#sha256:}" = "$(sha256sum "$tmp/$name" | cut -d' ' -f1)" ] || { log "$name: GitHub digest mismatch"; return 1; }
    fi
  done < <(jq -r '.assets[] | [.name, .size, .browser_download_url, (.digest // "")] | @tsv' <<<"$r")
  local sig; sig=$(verify_release "$tmp") || { log "REFUSED $tag"; return 1; }
  jq -n --arg tag "$tag" --arg sig "$sig" --arg date "$(jq -r .published_at <<<"$r")" \
    '{tag:$tag, signature:$sig, date:$date}' > "$tmp/META.json"
  chmod 755 "$tmp"; chmod 644 "$tmp"/*
  mv -T "$tmp" "$dest"
  log "mirrored $tag (signature: $sig)"
}

keep_tags=()
while IFS= read -r r; do
  tag=$(jq -r '.tag_name' <<<"$r")
  [[ $tag =~ $TAG_RE ]] || continue
  keep_tags+=("$tag")
  mirror_release "$r" || true     # one bad release must not block the others
done < <(jq -c '.[]' <<<"$releases")

# --- publish metadata in the same shape the Worker serves at /api/github ---
today=$(date -u +%F)
hist="$ROOT/data/history.json"
[ -f "$hist" ] || echo '[]' > "$hist"
jq --arg d "$today" --argjson s "$stars" '[.[] | select(.d != $d)] + [{d:$d, s:$s}] | .[-365:]' "$hist" > "$hist.new" && mv "$hist.new" "$hist"

out='[]'
for tag in "${keep_tags[@]:-}"; do
  [ -n "$tag" ] && [ -f "$ROOT/dl/$tag/META.json" ] || continue
  r=$(jq -c --arg t "$tag" '.[] | select(.tag_name==$t)' <<<"$releases")
  one=$(jq -n --argjson r "$r" --slurpfile m "$ROOT/dl/$tag/META.json" --arg dir "$ROOT/dl/$tag" '
    {tag:$r.tag_name, name:($r.name // $r.tag_name), date:$r.published_at,
     url:("/downloads/#" + $r.tag_name), prerelease:$r.prerelease, signature:$m[0].signature,
     assets:[$r.assets[] | {name:.name, size:.size, url:("/dl/" + $r.tag_name + "/" + .name)}]}')
  # add sha256 per asset
  withsum='[]'
  while IFS= read -r a; do
    n=$(jq -r .name <<<"$a")
    h=$(sha256sum "$ROOT/dl/$tag/$n" | cut -d' ' -f1)
    withsum=$(jq --argjson a "$a" --arg h "$h" '. + [$a + {sha256:$h}]' <<<"$withsum")
  done < <(jq -c '.assets[]' <<<"$one")
  out=$(jq --argjson one "$one" --argjson ws "$withsum" '. + [$one | .assets = $ws]' <<<"$out")
done
jq -n --arg repo "$REPO" --argjson stars "$stars" --arg now "$(date -u +%FT%TZ)" \
  --argjson rel "$out" --slurpfile hist "$hist" \
  '{repo:$repo, stars:$stars, fetchedAt:$now, releases:$rel, history:$hist[0]}' > "$ROOT/data/github.json.new"
mv "$ROOT/data/github.json.new" "$ROOT/data/github.json"

# --- stable "latest" link: newest non-prerelease that is mirrored ---
latest=$(jq -r '[.releases[] | select(.prerelease==false)][0].tag // empty' "$ROOT/data/github.json")
if [ -n "$latest" ]; then
  ln -s "$latest" "$ROOT/dl/.latest.new" && mv -T "$ROOT/dl/.latest.new" "$ROOT/dl/latest"
else
  rm -f "$ROOT/dl/latest"      # never leave a link to a release that is gone
fi

# --- prune releases that dropped out of the newest KEEP ---
for d in "$ROOT"/dl/*/; do
  n=$(basename "$d")
  [ "$n" = latest ] && continue
  [[ $n =~ $TAG_RE ]] || continue
  printf '%s\n' "${keep_tags[@]:-}" | grep -qx -- "$n" || { rm -rf "$d"; log "pruned $n"; }
done

# --- no-JavaScript downloads page (Tor Browser's Safest mode runs no scripts) ---
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
page="$ROOT/data/downloads/index.html.new"
{
cat <<'HTML'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Downloads: Sine Loco</title><meta name="color-scheme" content="dark light">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css"></head>
<body><header class="bar"><a class="mark" href="/"><img src="/favicon.svg" width="28" height="28" alt=""><span>Sine Loco</span></a></header>
<main class="wrap dlpage"><h1>Downloads</h1>
<p class="sub">Served from this onion address. Check every file before you run it.</p>
HTML
count=0
while IFS= read -r rel; do
  count=$((count+1))
  tag=$(jq -r .tag <<<"$rel"); date=$(jq -r .date <<<"$rel"); sig=$(jq -r .signature <<<"$rel")
  [[ $date =~ $DATE_RE ]] || date=""
  printf '<section class="dlrel" id="%s"><h2>%s</h2><p class="when">%s</p>\n' "$(esc <<<"$tag")" "$(esc <<<"$tag")" "${date%%T*}"
  case $sig in
    verified) echo '<p class="sigline good">SHA256SUMS signature verified by this mirror.</p>' ;;
    unverified) echo '<p class="sigline warn">A signature is published (SHA256SUMS.asc) but this mirror has no key to check it. Verify it yourself.</p>' ;;
    *) echo '<p class="sigline warn">This release has no signature. Compare the checksums with another copy.</p>' ;;
  esac
  echo '<ul class="dlfiles">'
  while IFS= read -r a; do
    n=$(jq -r .name <<<"$a"); s=$(jq -r .size <<<"$a"); h=$(jq -r .sha256 <<<"$a")
    printf '<li><a href="%s">%s</a><span class="sz">%s KB</span><code class="hash">%s</code></li>\n' \
      "/dl/$(esc <<<"$tag")/$(esc <<<"$n")" "$(esc <<<"$n")" "$(( (s+1023)/1024 ))" "$h"
  done < <(jq -c '.assets[]' <<<"$rel")
  echo '</ul></section>'
done < <(jq -c '.releases[]' "$ROOT/data/github.json")
if [ "$count" -eq 0 ]; then echo '<p>No release has been published yet.</p>'; fi
cat <<'HTML'
<section class="dlverify"><h2>Verify</h2>
<pre><code>sha256sum -c SHA256SUMS --ignore-missing
gpg --verify SHA256SUMS.asc SHA256SUMS</code></pre>
<p>The second command only applies when the release has a signature. Checksums that come from the same place as the file only catch corruption. Compare them with the copy on <a href="https://github.com/diePros/nerd-chat/releases">GitHub</a>, or rebuild the release yourself: the build is reproducible.</p></section>
</main></body></html>
HTML
} > "$page"
mv "$page" "$ROOT/data/downloads/index.html"
log "sync done: ${#keep_tags[@]} release(s) listed, $stars stars"
