# Secure file sharing (roadmap item, in progress)

## Principles
1. **Strip by allowlist, on the sender's machine, always.** `crates/strip` re-emits only what is needed to display a file and drops
   everything else (unknown segments, EXIF/XMP/ICC/comments/thumbnails, trailing data). Formats are recognised by content, never by
   name. Unknown formats are REFUSED (an explicit "send as opaque blob, NOT cleaned" mode is planned, clearly labelled).
2. **Authenticate through the session only** (tracker R7-I4): files travel as cells inside the Noise session with the per-message
   Ed25519 signature; a file hash inside the signed metadata message covers the content. Signed material outside the session is
   not post-quantum authentic.
3. **Neutral names**: the receiver saves under a random name by default; the real name is shown only if the user keeps it.
4. **RAM first, quarantine, no preview**: received files stay in RAM (size cap) until the user saves them; they are re-cleaned
   with the same stripper on receipt; never auto-opened, never rendered.
5. **Chunked + padded**: fixed 1 KiB cells already hide exact timing granularity; file length is padded to a bucket.

## Done
- `seburity-strip`: JPEG (APPn/COM/trailer dropped), PNG (only IHDR/PLTE/tRNS/IDAT/IEND kept, CRCs verified, trailer dropped),
  plain text (control/bidi/invisible characters removed). Planted-metadata tests prove each; output is idempotent; malformed
  input is refused; 16 MiB cap.

## Honest limits
- Pixel / entropy-coded data is copied as is: steganography, faces, handwriting, visible text are NOT removed.
- Dropping EXIF orientation / ICC profiles can change how an image looks (rotation, colours); the report says what was removed.
- No PDF/Office/audio/video/archive support yet: they are refused, because a parser we cannot audit is worse than no support.
- Planned hardening: re-encode instead of copy (needs a decoder = big attack surface; sandbox with seccomp/Landlock first).

## Next
Protocol messages (FILE_META signed with name-less size+hash, FILE_CHUNK), engine API `send_file`/`Event::File`, receiver quota,
TUI commands, standalone `seburity strip FILE`, then more formats.
