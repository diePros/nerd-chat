#!/usr/bin/env bash
# Build the release artifacts for the COMMITTED tree: static terminal binary, tarball, .deb, the GUI .deb, SHA256SUMS (and a detached signature if you have a key).
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
# GUI_BUILD_IMAGE=rust:1-bookworm builds it inside that container (Debian 12 = Tails 6: glibc 2.36, the .deb then needs only glibc >= 2.35).
if [ -n "${GUI_BUILD_IMAGE:-}" ]; then
  docker run --rm -v "$work":/src -e CARGO_TARGET_DIR=/src/target -e CARGO_INCREMENTAL=0 -e SOURCE_DATE_EPOCH=1700000000 \
    -e RUSTFLAGS="--remap-path-prefix=/src=/src --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup" \
    -w /src "$GUI_BUILD_IMAGE" cargo build --release --locked -p nerd-chat-gui
  docker run --rm -v "$work":/src "$GUI_BUILD_IMAGE" chown -R "$(id -u):$(id -g)" /src/target
else
( cd "$work"
  SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 \
  RUSTFLAGS="--remap-path-prefix=$work=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup" \
    cargo build --release --locked -p nerd-chat-gui )
fi
gbin="$work/target/release/nerd-chat-gui"
! LC_ALL=C grep -aq "$HOME" "$gbin" || { echo "the GUI binary contains the build user's home path"; exit 1; }
glibc=$(objdump -T "$gbin" | grep -o 'GLIBC_[0-9][0-9.]*' | sort -V | tail -1 | sed 's/GLIBC_//')
gdeb="$work/gdeb"; gdoc="$gdeb/usr/share/doc/nerd-chat-gui"
mkdir -p "$gdeb/DEBIAN" "$gdeb/usr/bin" "$gdoc" "$gdeb/usr/share/applications" "$gdeb/usr/share/icons/hicolor/scalable/apps"
install -m 0755 "$gbin" "$gdeb/usr/bin/nerd-chat-gui"
install -m 0644 packaging/nerd-chat.desktop "$gdeb/usr/share/applications/nerd-chat.desktop"
install -m 0644 packaging/nerd-chat.svg "$gdeb/usr/share/icons/hicolor/scalable/apps/nerd-chat.svg"
install -m 0644 LICENSE "$gdoc/copyright"
install -m 0644 README.md SECURITY.md docs/GETTING_STARTED.md docs/EXCHANGING_CONTACTS.md "$gdoc/"
gzip -9n < CHANGELOG.md > "$gdoc/changelog.gz"; chmod 0644 "$gdoc/changelog.gz"
gsize=$(du -sk "$gdeb/usr" | cut -f1)
cat > "$gdeb/DEBIAN/control" <<CTL
Package: nerd-chat-gui
Version: $ver
Section: net
Priority: optional
Architecture: amd64
Installed-Size: $gsize
Maintainer: nerd-chat maintainers <noreply@invalid>
Depends: libc6 (>= $glibc)
Recommends: tor, libgl1, libxkbcommon0, libwayland-client0, libx11-6
Description: serverless chat over Tor onion services (graphical app)
 Messages in RAM only, encrypted vault, shows up in the application menu.
 No screen-reader support on purpose (a screen reader would receive every
 message): see the README. Unaudited software: read SECURITY.md in
 /usr/share/doc/nerd-chat-gui before relying on it.
CTL
find "$gdeb" -type d -exec chmod 0755 {} +
find "$gdeb" -exec touch -h -d @1700000000 {} +
gdebname="nerd-chat-gui_${ver}_amd64.deb"
SOURCE_DATE_EPOCH=1700000000 fakeroot dpkg-deb --root-owner-group -Zgzip -z9 --build "$gdeb" "$out/$gdebname" >/dev/null
( cd "$out" && sha256sum "$asset.tar.gz" "$asset" "$deb" "$gdebname" > SHA256SUMS )
[ -z "${SIGN_KEY:-}" ] || gpg --local-user "$SIGN_KEY" --detach-sign --armor "$out/SHA256SUMS"
echo; cat "$out/SHA256SUMS"; echo "commit $commit"; ls -la "$out"
