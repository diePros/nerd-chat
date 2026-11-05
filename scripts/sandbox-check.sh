#!/usr/bin/env bash
# End-to-end check of the sandboxed cleaning helper with the STATIC musl release binary (the one that ships): a large PNG, a large
# plain-text file and a malformed file must go through `--strip` (which runs the helper under the seccomp filter) correctly, and the
# helper must report a seccomp FILTER in its own /proc status. Run from the repo root after:
#   cargo build --release --target x86_64-unknown-linux-musl -p nerd-chat-tui
set -euo pipefail
B=target/x86_64-unknown-linux-musl/release/nerd-chat
[ -x "$B" ] || { echo "build the musl release binary first"; exit 2; }
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
python3 - "$d" <<'P'
import zlib,struct,random,sys
d=sys.argv[1]
def chunk(t,x): return struct.pack(">I",len(x))+t+x+struct.pack(">I",zlib.crc32(t+x)&0xffffffff)
w=h=900; random.seed(7)
raw=b"".join(b"\x00"+bytes(random.randrange(256) for _ in range(w*3)) for _ in range(h))
open(d+"/big.png","wb").write(b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",struct.pack(">IIBBBBB",w,h,8,2,0,0,0))+chunk(b"tEXt",b"Author\x00someone")+chunk(b"IDAT",zlib.compress(raw,6))+chunk(b"IEND",b""))
open(d+"/big.txt","wb").write(("some text ​ more\n"*400000).encode()[:8*1024*1024-16])
open(d+"/bad.bin","wb").write(b"MZ\x90\x00 not an image")
P
fail=0
"$B" --strip "$d/big.png" "$d/out.png" --allow-swap | grep -q "removed: text chunks" && echo "ok  big PNG cleaned in the helper" || { echo "FAIL big PNG"; fail=1; }
"$B" --strip "$d/big.txt" "$d/out.txt" --text --allow-swap >/dev/null && [ "$(stat -c %s "$d/out.txt")" -lt "$(stat -c %s "$d/big.txt")" ] && echo "ok  8 MiB text cleaned in the helper" || { echo "FAIL big text"; fail=1; }
out=$("$B" --strip "$d/bad.bin" "$d/out.bad" --allow-swap 2>&1 || true)
if echo "$out" | grep -q "REFUSED"; then echo "ok  unsupported file refused"; else echo "FAIL unsupported file"; fail=1; fi
# the helper under the filter: start it, look at its status while it waits for stdin
"$B" --clean-worker < <(sleep 3) & pid=$!
for _ in $(seq 1 100); do grep -q '^Seccomp:.*2' /proc/$pid/status 2>/dev/null && break; sleep 0.05; done
grep -q '^Seccomp:.*2' /proc/$pid/status && grep -q '^NoNewPrivs:.*1' /proc/$pid/status && echo "ok  helper runs under a seccomp filter with no_new_privs" || { echo "FAIL helper has no seccomp filter"; fail=1; }
kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true
[ $fail = 0 ] && echo "SANDBOX CHECK PASSED" || { echo "SANDBOX CHECK FAILED"; exit 1; }
