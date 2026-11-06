#!/usr/bin/env bash
# Build the release artifacts for the COMMITTED tree: static binary, tarball, SHA256SUMS (and a detached signature if you have a key).
#   scripts/release.sh            -> dist/nerd-chat-<version>-x86_64-linux-musl/ + .tar.gz + SHA256SUMS
#   SIGN_KEY=<gpg key id> scripts/release.sh   -> also dist/SHA256SUMS.asc (gpg --detach-sign --armor)
# Same flags as scripts/repro-check.sh, so anybody can rebuild the same commit and compare the hash.
set -euo pipefail
TARGET=x86_64-unknown-linux-musl
root=$(git rev-parse --show-toplevel)
cd "$root"
[ -z "$(git status --porcelain)" ] || { echo "the git tree is not clean: commit first (the release is built from HEAD only)"; exit 1; }
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/tui/Cargo.toml | head -1)
commit=$(git rev-parse HEAD)
name="nerd-chat-$ver"
asset="nerd-chat-$ver-x86_64-linux-musl"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
git archive HEAD | tar -x -C "$work"
( cd "$work"
  SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 \
  RUSTFLAGS="--remap-path-prefix=$work=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup -C target-feature=+crt-static" \
    cargo build --release --locked --target $TARGET -p nerd-chat-tui )
bin="$work/target/$TARGET/release/nerd-chat"
file "$bin" | grep -q "static" || { echo "NOT a static binary"; exit 1; }
! LC_ALL=C grep -aq "$HOME" "$bin" || { echo "the binary contains the build user's home path"; exit 1; }
out="$root/dist"; rm -rf "$out"; mkdir -p "$out/$name"
cp "$bin" "$out/$name/nerd-chat"
cp LICENSE README.md SECURITY.md docs/GETTING_STARTED.md docs/BUILD_AND_RUN.md "$out/$name/"
printf 'nerd-chat %s\ncommit %s\nbuilt with: scripts/release.sh (see docs/BUILD_AND_RUN.md section 4 to verify)\n' "$ver" "$commit" > "$out/$name/BUILD-INFO.txt"
# deterministic tarball: sorted names, fixed owner and mtime, no gzip timestamp
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime=@1700000000 -C "$out" -cf - "$name" | gzip -9n > "$out/$asset.tar.gz"
cp "$bin" "$out/$asset"
( cd "$out" && sha256sum "$asset.tar.gz" "$asset" > SHA256SUMS )
[ -z "${SIGN_KEY:-}" ] || gpg --local-user "$SIGN_KEY" --detach-sign --armor "$out/SHA256SUMS"
echo; cat "$out/SHA256SUMS"; echo "commit $commit"; ls -la "$out"
