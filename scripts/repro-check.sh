#!/usr/bin/env bash
# Reproducible-build check: build the static binary twice from two copies of the source in
# DIFFERENT directories and compare SHA-256. Run from the repo root: scripts/repro-check.sh
set -euo pipefail
TARGET=x86_64-unknown-linux-musl
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for n in a/one b/two-longer-path; do
  mkdir -p "$work/$n"
  git -C "$root" archive HEAD | tar -x -C "$work/$n"
  ( cd "$work/$n"
    SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=$work/$n=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup -C target-feature=+crt-static" \
      cargo build --release --locked --target $TARGET -p sine-loco-tui >/dev/null )
done
h1=$(sha256sum "$work/a/one/target/$TARGET/release/sine-loco" | cut -d' ' -f1)
h2=$(sha256sum "$work/b/two-longer-path/target/$TARGET/release/sine-loco" | cut -d' ' -f1)
echo "$h1  build A"; echo "$h2  build B"
[ "$h1" = "$h2" ] && echo "REPRODUCIBLE (same machine, same toolchain)" || { echo "NOT reproducible"; exit 1; }
