# Secure file sharing

## How it works (inside the signed + encrypted session; nothing touches disk until you save)
1. **Sender** (`f` = JPEG/PNG, `t` = plain text): the file is cleaned by `crates/strip` (allowlist), the report is shown. Unknown
   formats are REFUSED. Only a CONNECTED contact can receive: files are never queued.
2. **Offer**: a signed message with `xfer id | padded bucket | mode | BLAKE2s-256(content)`. No file name, no MIME, no exact length.
3. **Receiver** sees "File offered (up to N KiB)" and must press `a`; before that not one content byte is sent and nothing is
   allocated. One transfer at a time per connection; a second offer while a file is unsaved is auto-declined (never silently replaced).
4. **Transfer**: `len(4) | content | zeros` padded to a power-of-two bucket (16 KiB .. 8 MiB), in 32-cell bursts so receiving,
   replies and keepalives are never starved. Timeouts: offer 120 s, stall 60 s. Misbehaving peers are cut off (6 bad frames).
5. **Quarantine**: the receiver checks layout/zero padding/hash, then re-cleans with its own stripper (mode from the offer; a
   declared "text" file is only ever plain-text cleaned). If it had to remove more than the sender claimed, a WARNING is shown.
6. **Save** (`s`): neutral random name `file-XXXXXXXX.ext` (absolute path shown), `create_new`, mode 0600, removed on write error;
   it leaves RAM when saved (`r` discards). Panic wipes everything. Global RAM budget 24 MiB for received files.

## What the stripper removes / validates
- JPEG: APPn (EXIF/GPS/XMP/ICC/thumbnails), COM, DNL, trailing data. Kept DQT/DHT/SOF/SOS/DRI are validated exactly (no padding
  bytes can hide payloads); arithmetic-coded JPEG refused.
- PNG: the concatenated IDAT data must be EXACTLY one well-formed zlib/deflate stream (own validator: header, all blocks, Adler-32,
  nothing after it) producing exactly the byte count IHDR implies (Adam7 included, bomb-bounded, 4 s / 20k-block work cap). Only IHDR (validated)/PLTE (palette images only)/tRNS (exact legal length per colour type)/IDAT/IEND kept, CRCs verified, everything else (tEXt/iTXt/zTXt/eXIf/tIME/
  iCCP/APNG/private) and trailing data dropped. Report lines are capped (chunk names are attacker-chosen: one aggregate line).
- Plain text (explicit): control, bidi, invisible, format, tag, variation-selector, private-use, noncharacter characters removed,
  combining runs capped. Structured documents (RTF/PDF/PS/XML/SVG/HTML/mail/shell) refused.

## Offline use
`sine-loco --strip IN OUT [--text]` cleans one file with no network and no vault; OUT must not exist (never overwritten), mode 0600.

## Honest limits
- **Cleaning protects against ACCIDENTAL metadata leaks, not against a sender who wants to smuggle data.** A cooperating sender can
  still hide a payload (e.g. a ZIP) in pixel data: inside a stored deflate block of a PNG, or as extra bytes after the entropy data
  of a JPEG; both survive cleaning and the file stays a valid image. Only decode + re-encode in a sandbox could change that.
  Table repetition is capped (8 DQT, 32 DHT) but zlib/entropy streams always have spare capacity.
- Pixel data / zlib stream copied unchanged: steganography, steganography inside valid pixel data, faces, handwriting and visible text stay. **Sensor noise (PRNU) and camera-specific quantisation tables can still
  identify a camera.** Re-encoding would remove tables but needs a decoder (large attack surface; sandbox first).
- Dropping EXIF orientation/ICC can change how an image looks.
- Cleaning does not make an image SAFE for whatever opens it: malicious image data passes through verbatim. Do not open received
  files on a machine you care about with a vulnerable viewer.
- PDF/Office/audio/video/archives: refused (no parser we can audit).
- The accepting side's presence is observable: a manual decline is immediate, an absent user's auto-decline takes 120 s.
- The sender's typed path passes through `input: String` (same class as R4-M2).

## Where the parsers run (cycle 24)
Cleaning of hostile files (a contact's file you receive, a file you send, `--strip`) does NOT run inside the process that holds
your keys. `sine-loco` starts a copy of itself as `sine-loco --clean-worker` (environment cleared, never sees keys or the vault)
with CPU (30 s), address-space (1 GiB), no-core-dump limits, `no_new_privs`, its own session (no controlling terminal), a
kill-with-parent signal (no helper outlives a panic wipe/exit) and a 25 s wall-clock kill in the parent; it refuses to run as root
or if any of these cannot be applied. A parser crash, endless loop or memory bomb only kills the helper (the job is refused). The
helper's answer is decoded as untrusted input (`sine_loco_strip::wire`: exact lengths, caps, control characters neutralised).
`--no-sandbox` cleans in-process instead.

**Syscall allowlist (cycle 26).** Before it reads any input the helper installs a seccomp-BPF allowlist (crate `crates/sandbox`, the only
crate with `unsafe`: ONE `prctl` call): `read` on fd 0, `write` on fd 1/2, ANONYMOUS `mmap` without PROT_EXEC (a file-backed mmap would let a compromised parser read/write any
descriptor inherited from the launcher), `munmap`, `mremap`, `madvise`, `brk`, `sigaltstack`, `clock_gettime` for the static clock ids
0..=15 only (a per-process CPU clock id is a side channel on the parent/Tor), `getrandom`, `exit_group`. Everything else kills the helper (SIGSYS): no `open`, `socket`,
`execve`, `unlink`, `rename`, `kill`, `ptrace`, `mprotect`, `close`, `fork`, 32-bit/x32 syscalls. The filter is tested by an in-test
BPF interpreter over all syscall numbers + 200k random inputs, by mutation checks, and against the real kernel (each forbidden
call kills a child with SIGSYS). x86_64 Linux only: elsewhere (or without seccomp) the helper refuses and files are refused unless
`--no-sandbox` is given. Residual: the parser can still lie in its answer (strict decoder) and burn CPU/memory up to the limits;
Tor, the vault and keys never exist in the helper. The rlimits (NOFILE/FSIZE/NPROC) are defence in depth, not the boundary.

Known limits of the filter (review 18): musl's allocator needs `mprotect` only when `brk` fails (near the 1 GiB address-space cap): then
the helper is killed and the file refused (fails closed, rare); the kernel logs seccomp kills (audit/dmesg), a small trace that a file
was refused; `scripts/sandbox-check.sh` re-checks the shipped static binary end to end.

## On the phone (Android)

The same protocol, with the phone's own front end. What differs:

- **Everything that parses a picture runs in an `isolatedProcess` service** (`CleanerService`): no permissions, no network, no access to the app's files, a separate UID, a FRESH process for every job. The process holds no key and no message. The main process only moves bytes (a picked picture is read as bytes, never decoded there; the answer is raw pixels or a `strip::wire` frame that the core decodes as untrusted input). When the isolated process cannot start, times out or fails, the file is REFUSED: the core's cleaner hook (`strip::set_cleaner`) is installed by the bridge and has no in-process fallback.
- **Sending:** the picture is picked with the system photo picker (no storage permission), re-encoded in the isolated process (decode with the system decoder, apply the rotation, scale the long edge to 1600 px, JPEG at quality 80 or lower to stay under 1.5 MB), then the core cleans it again (defence in depth) and offers it. Re-encoding removes ALL metadata and the camera's quantisation tables, which a metadata stripper alone cannot (see "Honest limits").
- **Receiving:** an offer card (the size is only the padded bucket) with Accept / Decline; the core re-cleans what arrives. Then View (decoded in the isolated process, shown in a secure window) / Save... (the user's own act, a neutral random name) / Discard. A photo is held in memory only and is gone when the app locks, is wiped or the contact is deleted. It is never queued, never in the history file and never in a backup.
- **Limits that remain:** a visible face or place stays visible; the pixels are re-encoded but a picture can still identify its source; a transfer is a burst of a few hundred cells that is distinguishable from chat on the wire (no cover traffic); the contact must be connected for the whole transfer (a lost connection cancels it, nothing resumes); one picture per contact at a time; `FLAG_SECURE` stops screenshots, not a second camera.
- **Not verified yet:** a real phone, real camera pictures (HEIC, very large ones), the transfer time over real Tor.
