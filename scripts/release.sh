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
# .deb (amd64): the same static binary, no maintainer scripts, deterministic (fixed mtimes, root owner, gzip -n)
debroot="$work/deb"; docdir="$debroot/usr/share/doc/nerd-chat"
mkdir -p "$debroot/DEBIAN" "$debroot/usr/bin" "$docdir"
install -m 0755 "$bin" "$debroot/usr/bin/nerd-chat"
install -m 0644 LICENSE "$docdir/copyright"
install -m 0644 README.md SECURITY.md docs/GETTING_STARTED.md docs/BUILD_AND_RUN.md "$docdir/"
gzip -9n < CHANGELOG.md > "$docdir/CHANGELOG.md.gz"; chmod 0644 "$docdir/CHANGELOG.md.gz"   # not Debian changelog syntax: do not call it changelog.gz
mkdir -p "$debroot/usr/share/man/man1" "$debroot/usr/share/lintian/overrides"
gzip -9n < packaging/nerd-chat.1 > "$debroot/usr/share/man/man1/nerd-chat.1.gz"; chmod 0644 "$debroot/usr/share/man/man1/nerd-chat.1.gz"
printf '%s\n' '# the binary is statically linked on purpose (musl): nothing to link against' 'nerd-chat: shared-library-lacks-prerequisites [usr/bin/nerd-chat]' > "$debroot/usr/share/lintian/overrides/nerd-chat"; chmod 0644 "$debroot/usr/share/lintian/overrides/nerd-chat"
size=$(du -sk "$debroot/usr" | cut -f1)
cat > "$debroot/DEBIAN/control" <<CTL
Package: nerd-chat
Version: $ver
Section: net
Priority: optional
Architecture: amd64
Installed-Size: $size
Maintainer: nerd-chat maintainers <noreply@invalid>
Recommends: tor
Description: serverless chat over Tor onion services (terminal UI)
 Static binary, messages in RAM only, encrypted vault. Unaudited software:
 read SECURITY.md in /usr/share/doc/nerd-chat before relying on it.
 It needs a tor binary for the default (spawn) mode; on Tails or Whonix use
 the system Tor.
CTL
find "$debroot" -type d -exec chmod 0755 {} +
find "$debroot" -exec touch -h -d @1700000000 {} +
deb="nerd-chat_${ver}_amd64.deb"
SOURCE_DATE_EPOCH=1700000000 fakeroot dpkg-deb --root-owner-group -Zgzip -z9 --build "$debroot" "$out/$deb" >/dev/null
# GUI .deb (amd64): a DYNAMICALLY linked glibc binary (the toolkit needs the system's X11/Wayland/OpenGL libraries at run time), the
# app-menu entry and the icon. Built with -p so that the GUI never pulls the terminal renderer. For portability build the release on the
# OLDEST system you want to support (the glibc version it needs is computed below and written into Depends).
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
gzip -9n < CHANGELOG.md > "$gdoc/CHANGELOG.md.gz"; chmod 0644 "$gdoc/CHANGELOG.md.gz"
mkdir -p "$gdeb/usr/share/man/man1"
gzip -9n < packaging/nerd-chat-gui.1 > "$gdeb/usr/share/man/man1/nerd-chat-gui.1.gz"; chmod 0644 "$gdeb/usr/share/man/man1/nerd-chat-gui.1.gz"
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
