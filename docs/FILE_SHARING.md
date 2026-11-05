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
- PNG: only IHDR (validated)/PLTE (len%3, <=768)/tRNS/IDAT/IEND kept, CRCs verified, everything else (tEXt/iTXt/zTXt/eXIf/tIME/
  iCCP/APNG/private) and trailing data dropped. Report lines are capped (chunk names are attacker-chosen: one aggregate line).
- Plain text (explicit): control, bidi, invisible, format, tag, variation-selector, private-use, noncharacter characters removed,
  combining runs capped. Structured documents (RTF/PDF/PS/XML/SVG/HTML/mail/shell) refused.

## Honest limits
- Pixel data / zlib stream copied unchanged: steganography, a ZIP/other polyglot tail inside the last IDAT (a zlib validator is
  planned), faces, handwriting and visible text stay. **Sensor noise (PRNU) and camera-specific quantisation tables can still
  identify a camera.** Re-encoding would remove tables but needs a decoder (large attack surface; sandbox first).
- Dropping EXIF orientation/ICC can change how an image looks.
- Cleaning does not make an image SAFE for whatever opens it: malicious image data passes through verbatim. Do not open received
  files on a machine you care about with a vulnerable viewer.
- PDF/Office/audio/video/archives: refused (no parser we can audit).
- The accepting side's presence is observable: a manual decline is immediate, an absent user's auto-decline takes 120 s.
- The sender's typed path passes through `input: String` (same class as R4-M2).
