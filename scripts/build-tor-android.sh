#!/usr/bin/env bash
# Build C tor as an Android executable named libtor.so (the only place Android 10+ lets an app run a program from: the native library directory).
# Sources are downloaded once, checked against the sha256 pinned below, and built with the NDK: OpenSSL and libevent static, zlib from the NDK sysroot.
#   usage: scripts/build-tor-android.sh [arm64-v8a|x86_64]       output: android/app/src/main/jniLibs/<abi>/libtor.so
# Needs ANDROID_HOME with the NDK, plus make, perl, a host C compiler is NOT needed. Reproducibility: fixed versions, SOURCE_DATE_EPOCH, -ffile-prefix-map, no build ids.
set -euo pipefail
ABI="${1:-arm64-v8a}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:?set ANDROID_HOME}/ndk/29.0.14206865}"
API=29
TOR=0.4.9.16;      TOR_SHA=6180e193152f4525bdca5475168419b2a2035b963c3c60162a187f86e6160e48
SSL=3.5.9;         SSL_SHA=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
EVENT=2.1.12-stable; EVENT_SHA=92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb
WORK="${TORBUILD_DIR:-$HOME/torbuild}"
case "$ABI" in
  arm64-v8a) TRIPLE=aarch64-linux-android; SSLTARGET=android-arm64 ;;
  x86_64)    TRIPLE=x86_64-linux-android;  SSLTARGET=android-x86_64 ;;
  *) echo "unknown ABI $ABI" >&2; exit 2 ;;
esac
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$BIN:$PATH" ANDROID_NDK_ROOT="$NDK" SOURCE_DATE_EPOCH=1700000000
export CC="$BIN/${TRIPLE}${API}-clang" AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" STRIP="$BIN/llvm-strip"
mkdir -p "$WORK/src" "$WORK/$ABI"
fetch() { # name url sha
  local f="$WORK/src/$1"
  [ -f "$f" ] || curl -fsSL -o "$f" "$2"
  echo "$3  $f" | sha256sum -c - >/dev/null || { echo "CHECKSUM MISMATCH for $1" >&2; rm -f "$f"; exit 1; }
}
fetch "tor-$TOR.tar.gz"          "https://dist.torproject.org/tor-$TOR.tar.gz" "$TOR_SHA"
fetch "openssl-$SSL.tar.gz"      "https://github.com/openssl/openssl/releases/download/openssl-$SSL/openssl-$SSL.tar.gz" "$SSL_SHA"
fetch "libevent-$EVENT.tar.gz"   "https://github.com/libevent/libevent/releases/download/release-$EVENT/libevent-$EVENT.tar.gz" "$EVENT_SHA"
PREFIX="$WORK/$ABI/prefix"; mkdir -p "$PREFIX"
FLAGS="-fPIC -O2 -ffile-prefix-map=$WORK=. -fno-ident"
if [ ! -f "$PREFIX/lib/libssl.a" ]; then
  rm -rf "$WORK/$ABI/openssl"; mkdir -p "$WORK/$ABI/openssl"; tar xzf "$WORK/src/openssl-$SSL.tar.gz" -C "$WORK/$ABI/openssl" --strip-components=1
  ( cd "$WORK/$ABI/openssl"
    ./Configure "$SSLTARGET" -D__ANDROID_API__=$API no-shared no-tests no-apps no-docs no-ssl3 no-comp no-engine no-dso no-legacy no-module no-asm "$FLAGS" --prefix="$PREFIX" --libdir=lib >/dev/null
    make -j"$(nproc)" build_libs >/dev/null && make install_dev >/dev/null )
fi
if [ ! -f "$PREFIX/lib/libevent.a" ]; then
  rm -rf "$WORK/$ABI/libevent"; mkdir -p "$WORK/$ABI/libevent"; tar xzf "$WORK/src/libevent-$EVENT.tar.gz" -C "$WORK/$ABI/libevent" --strip-components=1
  ( cd "$WORK/$ABI/libevent"
    ./configure --host="$TRIPLE" --prefix="$PREFIX" --disable-shared --enable-static --disable-openssl --disable-samples --disable-libevent-regress --with-pic CFLAGS="$FLAGS" >/dev/null
    make -j"$(nproc)" >/dev/null && make install >/dev/null )
fi
rm -rf "$WORK/$ABI/tor"; mkdir -p "$WORK/$ABI/tor"; tar xzf "$WORK/src/tor-$TOR.tar.gz" -C "$WORK/$ABI/tor" --strip-components=1
( cd "$WORK/$ABI/tor"
  ./configure --host="$TRIPLE" --prefix="$PREFIX" --enable-android --disable-asciidoc --disable-unittests --disable-tool-name-check --disable-system-torrc \
    --disable-module-relay --disable-module-dirauth --disable-zstd --disable-lzma --disable-seccomp --disable-libscrypt --disable-systemd --disable-html-manual --disable-manpage \
    --enable-static-openssl --enable-static-libevent --with-openssl-dir="$PREFIX" --with-libevent-dir="$PREFIX" \
    CFLAGS="$FLAGS" LDFLAGS="-pie -Wl,--build-id=none -Wl,-z,max-page-size=16384" >/dev/null
  make -j"$(nproc)" src/app/tor >/dev/null )
OUT="$ROOT/android/app/src/main/jniLibs/$ABI"; mkdir -p "$OUT"
"$STRIP" --strip-unneeded -o "$OUT/libtor.so" "$WORK/$ABI/tor/src/app/tor"
ls -la "$OUT/libtor.so"; sha256sum "$OUT/libtor.so"
