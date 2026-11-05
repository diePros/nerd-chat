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
`seburity --strip IN OUT [--text]` cleans one file with no network and no vault; OUT must not exist (never overwritten), mode 0600.

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
your keys. `seburity` starts a copy of itself as `seburity --clean-worker` (environment cleared, never sees keys or the vault)
with CPU (30 s), address-space (1 GiB), no-core-dump limits, `no_new_privs`, its own session (no controlling terminal), a
kill-with-parent signal (no helper outlives a panic wipe/exit) and a 25 s wall-clock kill in the parent; it refuses to run as root
or if any of these cannot be applied. A parser crash, endless loop or memory bomb only kills the helper (the job is refused). The
helper's answer is decoded as untrusted input (`seburity_strip::wire`: exact lengths, caps, control characters neutralised).
`--no-sandbox` cleans in-process instead.

**Syscall allowlist (cycle 26).** Before it reads any input the helper installs a seccomp-BPF allowlist (crate `crates/sandbox`, the only
crate with `unsafe`: ONE `prctl` call): `read` on fd 0, `write` on fd 1/2, `mmap` without PROT_EXEC, `munmap`, `mremap`, `madvise`,
`brk`, `sigaltstack`, `clock_gettime`, `getrandom`, `exit_group`. Everything else kills the helper (SIGSYS): no `open`, `socket`,
`execve`, `unlink`, `rename`, `kill`, `ptrace`, `mprotect`, `close`, `fork`, 32-bit/x32 syscalls. The filter is tested by an in-test
BPF interpreter over all syscall numbers + 200k random inputs, by mutation checks, and against the real kernel (each forbidden
call kills a child with SIGSYS). x86_64 Linux only: elsewhere (or without seccomp) the helper refuses and files are refused unless
`--no-sandbox` is given. Residual: the parser can still lie in its answer (strict decoder) and burn CPU/memory up to the limits;
Tor, the vault and keys never exist in the helper. The rlimits (NOFILE/FSIZE/NPROC) are defence in depth, not the boundary.
