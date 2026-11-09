#!/usr/bin/env bash
# Build C tor as an Android executable named libtor.so (the only place Android 10+ lets an app run a program from: the native library directory).
# Sources are downloaded, their PGP SIGNATURES are verified against the pinned signer fingerprints below (keys in scripts/tor-build-keys.asc) AND their sha256 against the pins,
# then OpenSSL, libevent and tor are ALWAYS rebuilt from scratch with the NDK (static; zlib from the NDK sysroot). Nothing cached is trusted.
#   usage: scripts/build-tor-android.sh [arm64-v8a|x86_64]       output: android/app/src/main/jniLibs/<abi>/libtor.so
# Needs ANDROID_HOME with NDK r29, gpg, make, perl, curl. Hardening is explicit (tor's own configure probes silently drop it under this clang) and CHECKED at the end.
set -euo pipefail
ABI="${1:-arm64-v8a}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:?set ANDROID_HOME}/ndk/29.0.14206865}"
API=29
TOR=0.4.9.16;        TOR_SHA=6180e193152f4525bdca5475168419b2a2035b963c3c60162a187f86e6160e48
SSL=3.5.9;           SSL_SHA=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
EVENT=2.1.12-stable; EVENT_SHA=92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb
# PRIMARY key fingerprints that may sign each source (tor: David Goulet / Alexander Faeroey; OpenSSL: the project's release certificate, listed in its doc/fingerprints.txt;
# libevent: Azat Khuzhin, named in libevent's Documentation/Developers.md). Pinned here, not fetched.
TOR_SIGNERS="B74417EDDF22AC9F9E90F49142E86A2A11F48D36 1C1BC007A9F607AA8152C040BEA7B180B1491921"
SSL_SIGNERS="B146647E45A7B33947AB226B2A2C87D161692D40"
EVENT_SIGNERS="9E3AC83A27974B84D1B3401DB86086848EF8686D"
# A FIXED path without the user's name: it ends up in strings inside the binary and decides whether the build is reproducible.
WORK="${TORBUILD_DIR:-/tmp/sine-loco-torbuild}"
case "$ABI" in
  arm64-v8a) TRIPLE=aarch64-linux-android; SSLTARGET=android-arm64;  ARCHFLAGS="-mbranch-protection=standard" ;;
  x86_64)    TRIPLE=x86_64-linux-android;  SSLTARGET=android-x86_64; ARCHFLAGS="-fcf-protection=full" ;;
  *) echo "unknown ABI $ABI" >&2; exit 2 ;;
esac
BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
export PATH="$BIN:$PATH" ANDROID_NDK_ROOT="$NDK" SOURCE_DATE_EPOCH=1700000000 TZ=UTC LC_ALL=C
mkdir -p "$WORK/bin"
REALCC="$BIN/${TRIPLE}${API}-clang"
export CC="$WORK/bin/${TRIPLE}${API}-clang" AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" STRIP="$BIN/llvm-strip" READELF="$BIN/llvm-readelf"
umask 077
mkdir -p -m 700 "$WORK"; [ "$(stat -c %u "$WORK")" = "$(id -u)" ] || { echo "$WORK is not ours" >&2; exit 1; }
mkdir -p "$WORK/src" "$WORK/bin"; rm -rf "$WORK/$ABI"; mkdir -p "$WORK/$ABI"
# the path-hiding flags live in a compiler WRAPPER, not in CFLAGS: OpenSSL and tor print their CFLAGS into the binary, and these flags name the builder's directories
printf '#!/bin/sh\nexec "%s" -ffile-prefix-map="%s"=/build -fdebug-prefix-map="%s"=/build -ffile-prefix-map="%s"=/ndk "$@"\n' "$REALCC" "$WORK" "$WORK" "$NDK" > "$CC"; chmod 700 "$CC"

GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; trap 'rm -rf "$GNUPGHOME"' EXIT
gpg --batch --quiet --import "$ROOT/scripts/tor-build-keys.asc" 2>/dev/null

fetch() { # name url
  [ -f "$WORK/src/$1" ] || curl -fsSL -o "$WORK/src/$1" "$2"
}
# gpg_ok <signature> <signed file> <allowed primary fingerprints>: a GOOD signature whose PRIMARY key is on the list
gpg_ok() {
  local out; out="$(gpg --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null || true)"
  local fpr; for fpr in $3; do
    echo "$out" | grep -q "^\[GNUPG:\] VALIDSIG .* $fpr\$" && return 0
  done
  return 1
}
sha_ok() { echo "$2  $WORK/src/$1" | sha256sum -c - >/dev/null; }

fetch "tor-$TOR.tar.gz" "https://dist.torproject.org/tor-$TOR.tar.gz"
fetch "tor-$TOR.tar.gz.sha256sum" "https://dist.torproject.org/tor-$TOR.tar.gz.sha256sum"
fetch "tor-$TOR.tar.gz.sha256sum.asc" "https://dist.torproject.org/tor-$TOR.tar.gz.sha256sum.asc"
fetch "openssl-$SSL.tar.gz" "https://github.com/openssl/openssl/releases/download/openssl-$SSL/openssl-$SSL.tar.gz"
fetch "openssl-$SSL.tar.gz.asc" "https://github.com/openssl/openssl/releases/download/openssl-$SSL/openssl-$SSL.tar.gz.asc"
fetch "libevent-$EVENT.tar.gz" "https://github.com/libevent/libevent/releases/download/release-$EVENT/libevent-$EVENT.tar.gz"
fetch "libevent-$EVENT.tar.gz.asc" "https://github.com/libevent/libevent/releases/download/release-$EVENT/libevent-$EVENT.tar.gz.asc"
sha_ok "tor-$TOR.tar.gz" "$TOR_SHA" && sha_ok "openssl-$SSL.tar.gz" "$SSL_SHA" && sha_ok "libevent-$EVENT.tar.gz" "$EVENT_SHA" || { echo "CHECKSUM MISMATCH (pinned sha256)" >&2; exit 1; }
gpg_ok "$WORK/src/tor-$TOR.tar.gz.sha256sum.asc" "$WORK/src/tor-$TOR.tar.gz.sha256sum" "$TOR_SIGNERS" || { echo "BAD or untrusted signature on tor's sha256sum" >&2; exit 1; }
( cd "$WORK/src" && grep " tor-$TOR.tar.gz\$" "tor-$TOR.tar.gz.sha256sum" | sha256sum -c - >/dev/null ) || { echo "tor tarball does not match its SIGNED sha256sum" >&2; exit 1; }
gpg_ok "$WORK/src/openssl-$SSL.tar.gz.asc" "$WORK/src/openssl-$SSL.tar.gz" "$SSL_SIGNERS" || { echo "BAD or untrusted signature on OpenSSL" >&2; exit 1; }
gpg_ok "$WORK/src/libevent-$EVENT.tar.gz.asc" "$WORK/src/libevent-$EVENT.tar.gz" "$EVENT_SIGNERS" || { echo "BAD or untrusted signature on libevent" >&2; exit 1; }
echo "signatures and checksums OK"

PREFIX="/opt/sine-loco-tor"; STAGE="$WORK/$ABI/stage"; mkdir -p "$STAGE"   # a fixed install prefix: the same strings on every machine
# explicit hardening: tor's configure probes for these flags fail under -Werror with this clang and drop them silently
HARDEN="-fstack-protector-strong -fwrapv -fstack-clash-protection $ARCHFLAGS -D_FORTIFY_SOURCE=3"
FLAGS="-fPIC -O2 $HARDEN"
LDHARD="-Wl,-z,relro,-z,now,-z,noexecstack -Wl,--build-id=none"

mkdir -p "$WORK/$ABI/openssl"; tar xzf "$WORK/src/openssl-$SSL.tar.gz" -C "$WORK/$ABI/openssl" --strip-components=1
( cd "$WORK/$ABI/openssl"
  ./Configure "$SSLTARGET" -D__ANDROID_API__=$API no-shared no-tests no-apps no-docs no-ssl3 no-comp no-engine no-dso no-legacy no-module $FLAGS --prefix="$PREFIX" --openssldir=/nonexistent --libdir=lib >/dev/null
  make -j"$(nproc)" build_libs >/dev/null && make DESTDIR="$STAGE" install_dev >/dev/null )
mkdir -p "$WORK/$ABI/libevent"; tar xzf "$WORK/src/libevent-$EVENT.tar.gz" -C "$WORK/$ABI/libevent" --strip-components=1
( cd "$WORK/$ABI/libevent"
  ./configure --host="$TRIPLE" --prefix="$PREFIX" --disable-shared --enable-static --disable-openssl --disable-samples --disable-libevent-regress --with-pic CFLAGS="$FLAGS" >/dev/null
  make -j"$(nproc)" >/dev/null && make DESTDIR="$STAGE" install >/dev/null )
mkdir -p "$WORK/$ABI/tor"; tar xzf "$WORK/src/tor-$TOR.tar.gz" -C "$WORK/$ABI/tor" --strip-components=1
( cd "$WORK/$ABI/tor"
  ./configure --host="$TRIPLE" --prefix="$PREFIX" --enable-android --disable-asciidoc --disable-unittests --disable-tool-name-check --disable-system-torrc \
    --disable-module-relay --disable-module-dirauth --disable-zstd --disable-lzma --disable-seccomp --disable-libscrypt --disable-systemd --disable-html-manual --disable-manpage \
    --enable-static-openssl --enable-static-libevent --with-openssl-dir="$STAGE$PREFIX" --with-libevent-dir="$STAGE$PREFIX" \
    CFLAGS="$FLAGS" LDFLAGS="-pie -Wl,-z,max-page-size=16384 $LDHARD" >/dev/null
  make -j"$(nproc)" src/app/tor >/dev/null )
OUT="$ROOT/android/app/src/main/jniLibs/$ABI"; mkdir -p "$OUT"
"$STRIP" --strip-unneeded -o "$OUT/libtor.so" "$WORK/$ABI/tor/src/app/tor"

# ---- checks: the build must FAIL if the hardening or the privacy of the binary is not there ----
LIB="$OUT/libtor.so"; fail=0
dyn="$("$READELF" -d "$LIB")"; seg="$("$READELF" -lW "$LIB")"; syms="$("$READELF" --dyn-syms "$LIB")"
grep -q "__stack_chk_fail" <<<"$syms" || { echo "CHECK FAILED: no stack protector (__stack_chk_fail not imported)"; fail=1; }
grep -q "BIND_NOW" <<<"$dyn" || { echo "CHECK FAILED: no BIND_NOW"; fail=1; }
grep -q "GNU_RELRO" <<<"$seg" || { echo "CHECK FAILED: no RELRO"; fail=1; }
grep "GNU_STACK" <<<"$seg" | grep -q "RWE" && { echo "CHECK FAILED: executable stack"; fail=1; }
grep LOAD <<<"$seg" | grep -qv "0x4000" && { echo "CHECK FAILED: LOAD segments not 16 KB aligned"; fail=1; }
if [ "$ABI" = arm64-v8a ]; then grep -q "BTI" <<<"$("$READELF" -n "$LIB")" || { echo "CHECK FAILED: no BTI note"; fail=1; }; fi
STR="$(strings "$LIB")"   # a variable, not a pipe: `grep -q` closing the pipe early would make a pipefail shell report "not found"
for s in "$HOME" "$(id -un)" "$WORK" "$ROOT" "$NDK"; do [ -n "$s" ] && [ "$s" != / ] && grep -qF "$s" <<<"$STR" && { echo "CHECK FAILED: the binary contains '$s'"; fail=1; }; done
[ "$fail" = 0 ] || { rm -f "$LIB"; echo "libtor.so removed: fix the build" >&2; exit 1; }
ls -la "$LIB"; sha256sum "$LIB"
