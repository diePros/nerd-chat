//! Metadata stripping by ALLOWLIST: we re-emit only the structural parts of a JPEG/PNG that are needed to display it and
//! drop everything else (APPn/EXIF/XMP/ICC/comments/thumbnails, unknown chunks, trailing data). Kept segments are validated
//! EXACTLY (no extra bytes). Formats are recognised by content, never by name; everything else is REFUSED. Plain text is an
//! explicit `Mode::PlainText` choice and structured text documents (RTF/PDF/SVG/XML/HTML...) are refused even then.
//!
//! Honest limits (see docs/FILE_SHARING.md): entropy-coded pixel data / zlib streams are copied unchanged (steganography, a
//! polyglot tail inside the last IDAT, camera sensor noise, quantisation tables that fingerprint a camera model, faces,
//! visible text are NOT removed); dropping EXIF orientation/ICC can change how an image looks; cleaning does NOT make a
//! malicious image safe for a viewer. Pure Rust, bounded allocation.
#![forbid(unsafe_code)]

pub mod wire;

/// Largest input we clean (and the largest file the chat sends).
pub const MAX_INPUT: usize = 8 * 1024 * 1024;
/// Report lines are capped so a hostile file cannot flood the UI with them.
const MAX_REPORT: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StripError {
    #[error("file too large (max 8 MiB)")]
    TooLarge,
    #[error("unsupported or unrecognised format (refused: it cannot be cleaned)")]
    Unsupported,
    #[error("looks like a structured document format (RTF/PDF/SVG/XML/HTML/script...) whose metadata cannot be removed here: refused")]
    StructuredText,
    #[error("malformed {0} file: {1}")]
    Malformed(&'static str, &'static str),
    /// Refused by the sandboxed cleaning helper (its own message, sanitised) or its answer was unusable.
    #[error("refused: {0}")]
    Refused(String),
}

/// The cleaner used by `clean_hooked`: the app installs one that runs `clean` in a resource-limited child process.
pub type CleanFn = fn(&[u8], Mode) -> Result<Cleaned, StripError>;
static CLEANER: std::sync::OnceLock<CleanFn> = std::sync::OnceLock::new();

/// Install the process-wide cleaner (first call wins). Without one, `clean_hooked` cleans in-process.
pub fn set_cleaner(f: CleanFn) { let _ = CLEANER.set(f); }

/// What the chat engine calls for hostile input: the installed (sandboxed) cleaner, else `clean`.
pub fn clean_hooked(d: &[u8], mode: Mode) -> Result<Cleaned, StripError> { match CLEANER.get() { Some(f) => f(d, mode), None => clean(d, mode) } }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format { Jpeg, Png, Text }

/// `Auto` accepts ONLY formats we can clean structurally (JPEG, PNG). `PlainText` is an explicit user choice: only
/// invisible/control characters are removed; document metadata inside text-based formats is NOT understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Auto, PlainText }

#[derive(Debug)]
pub struct Cleaned {
    pub format: Format,
    pub data: Vec<u8>,
    /// Human-readable before/after report (at most 16 lines).
    pub report: Vec<String>,
}

pub fn clean(d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
    match mode {
        Mode::PlainText => text(d),
        Mode::Auto => {
            if d.starts_with(&[0xFF, 0xD8, 0xFF]) { jpeg(d) }
            else if d.starts_with(b"\x89PNG\r\n\x1a\n") { png(d) }
            else { Err(StripError::Unsupported) }
        }
    }
}

fn finish(dropped: std::collections::BTreeMap<String, (usize, usize)>) -> Vec<String> {
    let mut report: Vec<String> = dropped.into_iter().take(MAX_REPORT).map(|(k, (n, b))| format!("{k}: {} item(s), {b} bytes removed", n.max(1))).collect();
    report.truncate(MAX_REPORT);
    report
}

type Dropped = std::collections::BTreeMap<String, (usize, usize)>;

// ---------------- JPEG ----------------
/// Exact structural validation of the segments we keep (nothing may hide in extra bytes).
fn jpeg_segment_ok(m: u8, body: &[u8]) -> Option<usize> {
    let ok = |b: bool| if b { Some(1) } else { None };
    match m {
        0xDB => { // DQT: (Pq|Tq, 64*(Pq+1) bytes)*
            let (mut i, mut n) = (0, 0);
            if body.is_empty() { return None; }
            while i < body.len() {
                let (pq, tq) = (body[i] >> 4, body[i] & 15);
                if pq > 1 || tq > 3 { return None; }
                i += 1 + 64 * (pq as usize + 1); n += 1;
            }
            if i == body.len() { Some(n) } else { None }
        }
        0xC4 => { // DHT: (Tc|Th, 16 counts, symbols)*
            let (mut i, mut tables) = (0, 0);
            if body.is_empty() { return None; }
            while i < body.len() {
                if body.len() < i + 17 { return None; }
                let (tc, th) = (body[i] >> 4, body[i] & 15);
                if tc > 1 || th > 3 { return None; }
                let n: usize = body[i + 1..i + 17].iter().map(|&c| c as usize).sum();
                if n > 256 { return None; }
                i += 17 + n; tables += 1;
            }
            if i == body.len() { Some(tables) } else { None }
        }
        0xC0..=0xC3 | 0xC5..=0xC7 => { // SOF (Huffman): P, Y, X, Nf, 3*Nf
            ok(body.len() >= 6 && matches!(body[0], 8 | 12 | 16) && (1..=4).contains(&body[5]) && body.len() == 6 + 3 * body[5] as usize
                && u16::from_be_bytes([body[1], body[2]]) != 0 && u16::from_be_bytes([body[3], body[4]]) != 0)
        }
        0xDA => ok(!body.is_empty() && (1..=4).contains(&body[0]) && body.len() == 1 + 2 * body[0] as usize + 3), // SOS
        0xDD => ok(body.len() == 2), // DRI
        _ => None,
    }
}

fn jpeg(d: &[u8]) -> Result<Cleaned, StripError> {
    const M: &str = "JPEG";
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(d.len())); // wiped on every error path
    let mut dropped = Dropped::new();
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut i = 2;
    let (mut seen_sof, mut seen_scan) = (false, false);
    let (mut tables_q, mut tables_h) = (0usize, 0usize);
    loop {
        if i >= d.len() { return Err(StripError::Malformed(M, "missing EOI")); }
        if d[i] != 0xFF { return Err(StripError::Malformed(M, "expected marker")); }
        while i < d.len() && d[i] == 0xFF { i += 1; }
        if i >= d.len() { return Err(StripError::Malformed(M, "truncated")); }
        let m = d[i]; i += 1;
        match m {
            0xD9 => {
                if !seen_scan { return Err(StripError::Malformed(M, "no image data")); }
                out.extend_from_slice(&[0xFF, 0xD9]);
                if i < d.len() { dropped.entry("data after end of image".into()).or_default().1 += d.len() - i; }
                break;
            }
            0x00 | 0x01 | 0xD0..=0xD8 => return Err(StripError::Malformed(M, "unexpected standalone marker")),
            0xC8..=0xCF => return Err(StripError::Unsupported), // arithmetic coding / reserved: not supported
            _ => {}
        }
        if i + 2 > d.len() { return Err(StripError::Malformed(M, "truncated segment")); }
        let len = u16::from_be_bytes([d[i], d[i + 1]]) as usize;
        if len < 2 || i + len > d.len() { return Err(StripError::Malformed(M, "bad segment length")); }
        let body = &d[i + 2..i + len];
        let keep = matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC4 | 0xDB | 0xDD | 0xDA);
        let seg = &d[i..i + len];
        i += len;
        if keep {
            let Some(n) = jpeg_segment_ok(m, body) else { return Err(StripError::Malformed(M, "invalid or padded structural segment")); };
            // table redefinition is legal but unbounded repetition is a covert channel: legitimate files need a handful
            if m == 0xDB { tables_q += n; if tables_q > 8 { return Err(StripError::Malformed(M, "too many quantisation tables")); } }
            if m == 0xC4 { tables_h += n; if tables_h > 32 { return Err(StripError::Malformed(M, "too many Huffman tables")); } }
            if matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7) { if seen_sof { return Err(StripError::Malformed(M, "second frame header")); } seen_sof = true; }
            out.extend_from_slice(&[0xFF, m]);
            out.extend_from_slice(seg);
            if m == 0xDA {
                if !seen_sof { return Err(StripError::Malformed(M, "scan before frame header")); }
                seen_scan = true;
                let start = i;
                while i + 1 < d.len() {
                    if d[i] == 0xFF && d[i + 1] != 0x00 && !(0xD0..=0xD7).contains(&d[i + 1]) && d[i + 1] != 0xFF { break; }
                    i += 1;
                }
                if i + 1 >= d.len() { return Err(StripError::Malformed(M, "truncated scan")); }
                out.extend_from_slice(&d[start..i]);
            }
        } else {
            let name = match m { 0xE0..=0xEF => format!("application segment APP{} (EXIF/XMP/ICC/thumbnail/...)", m - 0xE0), 0xFE => "comment".into(), 0xDC => "line-count (DNL) segment".into(), _ => "other segment".into() };
            let e = dropped.entry(name).or_default(); e.0 += 1; e.1 += len + 2;
        }
    }
    Ok(Cleaned { format: Format::Jpeg, data: std::mem::take(&mut *out), report: finish(dropped) })
}

// ---------------- zlib/deflate validator (no output kept) ----------------
/// Validates a zlib stream EXACTLY: header, every deflate block, the Adler-32 trailer, and that nothing follows it. Output is
/// only counted (bounded by `expect`), never stored, so a hostile stream cannot allocate. Used to prove the concatenated IDAT
/// data is one well-formed image stream of exactly the size IHDR implies (no polyglot tail, no bytes after the stream).
fn zlib_valid(z: &[u8], expect: usize) -> bool {
    struct Bits<'a> { d: &'a [u8], pos: usize, bit: u32, nbits: u32 }
    impl Bits<'_> {
        fn need(&mut self, n: u32) -> Option<u32> {
            while self.nbits < n { let b = *self.d.get(self.pos)?; self.pos += 1; self.bit |= (b as u32) << self.nbits; self.nbits += 8; }
            let v = self.bit & ((1u32 << n) - 1); self.bit >>= n; self.nbits -= n; Some(v)
        }
    }
    #[derive(Clone)]
    struct Huff { count: [u16; 16], symbol: Vec<u16> }
    fn build(lengths: &[u8]) -> Option<Huff> {
        let mut count = [0u16; 16];
        for &l in lengths { count[l as usize] += 1; }
        let mut left: i32 = 1;
        for len in 1..16 { left = (left << 1) - count[len] as i32; if left < 0 { return None; } }
        let mut offs = [0u16; 16];
        for len in 1..15 { offs[len + 1] = offs[len] + count[len]; }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() { if l != 0 { symbol[offs[l as usize] as usize] = sym as u16; offs[l as usize] += 1; } }
        Some(Huff { count, symbol })
    }
    fn decode(b: &mut Bits, h: &Huff) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.need(1)? as i32;
            let c = h.count[len] as i32;
            if code - c < first { return h.symbol.get((index + (code - first)) as usize).copied(); }
            index += c; first += c; first <<= 1; code <<= 1;
        }
        None
    }
    const LBASE: [u16; 29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    const LEXT: [u8; 29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    const DBASE: [u16; 30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    const DEXT: [u8; 30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];

    if z.len() < 6 { return false; }
    let (cmf, flg) = (z[0], z[1]);
    if cmf & 0x0F != 8 || cmf >> 4 > 7 || !((cmf as u16) << 8 | flg as u16).is_multiple_of(31) || flg & 0x20 != 0 { return false; }
    let mut b = Bits { d: &z[2..], pos: 0, bit: 0, nbits: 0 };
    let mut win = zeroize::Zeroizing::new(vec![0u8; 32768]);
    let (mut out, mut a, mut bsum) = (0usize, 1u32, 0u32);
    // work bounds: the validator must never hold a thread (and the panic key) for long on hostile input
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let (mut blocks, mut empty_blocks) = (0u32, 0u32);
    let mut emit = |byte: u8, win: &mut Vec<u8>, out: &mut usize| -> bool {
        if *out >= expect { return false; }
        if *out & 0xFFFF == 0 && std::time::Instant::now() > deadline { return false; }
        win[*out & 32767] = byte; *out += 1;
        a = (a + byte as u32) % 65521; bsum = (bsum + a) % 65521;
        true
    };
    loop {
        blocks += 1;
        if blocks > 1_000_000 || empty_blocks > 2_000 || std::time::Instant::now() > deadline { return false; }
        let out_before = out;
        let Some(last) = b.need(1) else { return false };
        let Some(ty) = b.need(2) else { return false };
        match ty {
            0 => {
                b.bit = 0; b.nbits = 0; // drop to byte boundary
                let Some(h) = b.d.get(b.pos..b.pos + 4) else { return false };
                let (len, nlen) = (u16::from_le_bytes([h[0], h[1]]), u16::from_le_bytes([h[2], h[3]]));
                if len != !nlen { return false; }
                b.pos += 4;
                let Some(data) = b.d.get(b.pos..b.pos + len as usize) else { return false };
                for &byte in data { if !emit(byte, &mut win, &mut out) { return false; } }
                b.pos += len as usize;
            }
            1 | 2 => {
                let (lit, dist): (std::borrow::Cow<Huff>, std::borrow::Cow<Huff>) = if ty == 1 {
                    static FIXED: std::sync::OnceLock<Option<(Huff, Huff)>> = std::sync::OnceLock::new();
                    let f = FIXED.get_or_init(|| {
                        let mut l = [0u8; 288];
                        for (i, v) in l.iter_mut().enumerate() { *v = if i < 144 { 8 } else if i < 256 { 9 } else if i < 280 { 7 } else { 8 }; }
                        Some((build(&l)?, build(&[5u8; 30])?))
                    });
                    let Some((a, c)) = f else { return false };
                    (std::borrow::Cow::Borrowed(a), std::borrow::Cow::Borrowed(c))
                } else {
                    let (Some(nlen), Some(ndist), Some(ncode)) = (b.need(5), b.need(5), b.need(4)) else { return false };
                    let (nlen, ndist, ncode) = (nlen as usize + 257, ndist as usize + 1, ncode as usize + 4);
                    if nlen > 286 || ndist > 30 { return false; }
                    const ORDER: [usize; 19] = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
                    let mut cl = [0u8; 19];
                    for &o in ORDER.iter().take(ncode) { let Some(v) = b.need(3) else { return false }; cl[o] = v as u8; }
                    let Some(ch) = build(&cl) else { return false };
                    let mut lens = vec![0u8; nlen + ndist];
                    let mut i = 0;
                    while i < nlen + ndist {
                        let Some(sym) = decode(&mut b, &ch) else { return false };
                        if sym < 16 { lens[i] = sym as u8; i += 1; continue; }
                        let (prev, rep) = match sym {
                            16 => { if i == 0 { return false; } let Some(r) = b.need(2) else { return false }; (lens[i - 1], 3 + r as usize) }
                            17 => { let Some(r) = b.need(3) else { return false }; (0, 3 + r as usize) }
                            _ => { let Some(r) = b.need(7) else { return false }; (0, 11 + r as usize) }
                        };
                        if i + rep > nlen + ndist { return false; }
                        for _ in 0..rep { lens[i] = prev; i += 1; }
                    }
                    if lens[256] == 0 { return false; }
                    let (Some(a), Some(c)) = (build(&lens[..nlen]), build(&lens[nlen..])) else { return false };
                    (std::borrow::Cow::Owned(a), std::borrow::Cow::Owned(c))
                };
                loop {
                    let Some(sym) = decode(&mut b, lit.as_ref()) else { return false };
                    if sym < 256 { if !emit(sym as u8, &mut win, &mut out) { return false; } continue; }
                    if sym == 256 { break; }
                    let sym = sym as usize - 257;
                    if sym >= 29 { return false; }
                    let Some(e) = b.need(LEXT[sym] as u32) else { return false };
                    let len = LBASE[sym] as usize + e as usize;
                    let Some(ds) = decode(&mut b, dist.as_ref()) else { return false };
                    let ds = ds as usize;
                    if ds >= 30 { return false; }
                    let Some(e) = b.need(DEXT[ds] as u32) else { return false };
                    let d = DBASE[ds] as usize + e as usize;
                    if d > out || d > 32768 { return false; }
                    for _ in 0..len { let byte = win[(out - d) & 32767]; if !emit(byte, &mut win, &mut out) { return false; } }
                }
            }
            _ => return false,
        }
        if out == out_before { empty_blocks += 1; } // blocks that emit nothing are the only pure-overhead kind: cap them hard
        if last == 1 { break; }
    }
    if out != expect { return false; }
    // byte-align, then exactly the Adler-32 trailer and nothing else
    let used = b.pos - (b.nbits / 8) as usize;
    let rest = &b.d[used.min(b.d.len())..];
    rest.len() == 4 && u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) == (bsum << 16 | a)
}

/// Raw (decompressed) size IHDR implies, including filter bytes (Adam7 handled).
fn raw_size(w: u64, h: u64, depth: u8, ct: u8, interlace: u8) -> Option<usize> {
    // u128 throughout: w,h < 2^31 each, so no intermediate can overflow (a panic here would abort the whole app)
    let ch: u128 = match ct { 0 => 1, 2 => 3, 3 => 1, 4 => 2, 6 => 4, _ => return None };
    let bits = ch * depth as u128;
    let row = |pw: u128| (pw * bits).div_ceil(8) + 1;
    let (w, h) = (w as u128, h as u128);
    let total: u128 = if interlace == 0 { row(w) * h } else {
        let mut t = 0u128;
        for (x0, y0, dx, dy) in [(0u128, 0u128, 8u128, 8u128), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)] {
            if w > x0 && h > y0 { t += row((w - x0).div_ceil(dx)) * (h - y0).div_ceil(dy); }
        }
        t
    };
    if total > 128 * 1024 * 1024 { return None; } // decompression-bomb guard: bounds the CPU the validator can be made to spend
    usize::try_from(total).ok()
}

// ---------------- PNG ----------------
fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (n, e) in t.iter_mut().enumerate() {
            let mut c = n as u32;
            for _ in 0..8 { c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 }; }
            *e = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &b in data { c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8); }
    c ^ 0xFFFF_FFFF
}

fn png(d: &[u8]) -> Result<Cleaned, StripError> {
    const M: &str = "PNG";
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(d.len()));
    out.extend_from_slice(&d[..8]);
    let mut i = 8;
    let mut dropped = Dropped::new();
    let (mut ihdr, mut idat, mut iend, mut plte, mut trns) = (false, false, false, false, false);
    let mut depth = 0u8;
    let mut dims = (0u64, 0u64, 0u8, 0u8);
    let mut z: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(Vec::with_capacity(d.len()));
    let mut ctype = 0u8;
    let mut plte_entries = 0usize;
    let mut last_idat_end = 0usize;
    while i < d.len() && !iend {
        if i + 12 > d.len() { return Err(StripError::Malformed(M, "truncated chunk")); }
        let len = u32::from_be_bytes(d[i..i + 4].try_into().unwrap()) as usize;
        if len > 0x7FFF_FFFF || i + 12 + len > d.len() { return Err(StripError::Malformed(M, "bad chunk length")); }
        let ty = &d[i + 4..i + 8];
        let body = &d[i + 8..i + 8 + len];
        let crc = u32::from_be_bytes(d[i + 8 + len..i + 12 + len].try_into().unwrap());
        if crc32(&d[i + 4..i + 8 + len]) != crc { return Err(StripError::Malformed(M, "chunk CRC mismatch")); }
        if !ty.iter().all(u8::is_ascii_alphabetic) { return Err(StripError::Malformed(M, "bad chunk type")); }
        let whole = &d[i..i + 12 + len];
        match ty {
            b"IHDR" => {
                if ihdr || i != 8 || len != 13 { return Err(StripError::Malformed(M, "bad IHDR")); }
                let (w, h) = (u32::from_be_bytes(body[0..4].try_into().unwrap()), u32::from_be_bytes(body[4..8].try_into().unwrap()));
                depth = body[8];
                dims = (w as u64, h as u64, body[9], body[12]);
                ctype = body[9];
                if w == 0 || h == 0 || w > 0x7FFF_FFFF || h > 0x7FFF_FFFF || !matches!(depth, 1 | 2 | 4 | 8 | 16) || !matches!(body[9], 0 | 2 | 3 | 4 | 6) || body[10] != 0 || body[11] != 0 || body[12] > 1 {
                    return Err(StripError::Malformed(M, "invalid IHDR values"));
                }
                ihdr = true; out.extend_from_slice(whole);
            }
            // PLTE is kept only where it is REQUIRED (palette images); a "suggested palette" on other colour types is dropped.
            b"PLTE" if ctype == 3 => {
                if !ihdr || idat || plte || trns || len == 0 || !len.is_multiple_of(3) || len > 768 || len / 3 > (1usize << depth.min(8)) { return Err(StripError::Malformed(M, "invalid PLTE")); }
                plte = true; plte_entries = len / 3; out.extend_from_slice(whole);
            }
            // tRNS only with its exact legal length per colour type (grey 2, RGB 6, palette <= entries); never with alpha types.
            b"tRNS" if !trns && !idat && ihdr && match ctype { 0 => len == 2, 2 => len == 6, 3 => plte && len <= plte_entries, _ => false } => {
                trns = true; out.extend_from_slice(whole);
            }
            b"IDAT" => { if !ihdr { return Err(StripError::Malformed(M, "IDAT before IHDR")); } if idat && i != last_idat_end { return Err(StripError::Malformed(M, "IDAT chunks not consecutive")); } idat = true; z.extend_from_slice(body); last_idat_end = i + 12 + len; out.extend_from_slice(whole); }
            b"IEND" => { if !idat || len != 0 { return Err(StripError::Malformed(M, "bad IEND")); } out.extend_from_slice(whole); iend = true; }
            _ => {
                let name = match ty {
                    b"tEXt" | b"zTXt" | b"iTXt" => "text chunks (author/comment/software/XMP)",
                    b"eXIf" => "EXIF block",
                    b"PLTE" | b"tRNS" => "palette/transparency data not needed for this image type",
                    b"tIME" => "modification time",
                    b"iCCP" => "ICC colour profile",
                    _ => "other ancillary chunks", // ONE aggregate entry: chunk types are attacker-chosen
                };
                let e = dropped.entry(name.to_string()).or_default(); e.0 += 1; e.1 += whole.len();
            }
        }
        i += 12 + len;
    }
    if !iend { return Err(StripError::Malformed(M, "missing IEND")); }
    if ctype == 3 && !plte { return Err(StripError::Malformed(M, "palette image without PLTE")); }
    let expect = raw_size(dims.0, dims.1, depth, dims.2, dims.3).ok_or(StripError::Malformed(M, "implausible image size"))?;
    if !zlib_valid(&z, expect) { return Err(StripError::Malformed(M, "image data is not exactly one well-formed zlib stream of the size IHDR implies")); }
    if i < d.len() { dropped.entry("data after IEND".into()).or_default().1 += d.len() - i; }
    Ok(Cleaned { format: Format::Png, data: std::mem::take(&mut *out), report: finish(dropped) })
}

// ---------------- plain text (explicit choice) ----------------
/// Content that is really a structured document: refused even in plain-text mode (its metadata would pass untouched).
fn looks_structured(s: &str) -> bool {
    // skip EVERYTHING invisible or blank first (NBSP, ideographic space, combining marks, bidi/format characters...)
    let t = s.trim_start_matches(|c: char| c.is_whitespace() || sine_loco_core::text::is_unsafe_char(c) || sine_loco_core::text::is_combining(c));
    let lower: String = t.chars().take(64).flat_map(char::to_lowercase).collect();
    if ["{\\rtf", "%pdf", "%!", "<?xml", "<svg", "<!doctype", "<html", "<", "begin:v", "#!", "from ", "mime-version"].iter().any(|p| lower.starts_with(p)) { return true; }
    // RFC 822 / e-mail headers ("Delivered-To:", "Received:", "X-Originating-IP:" ... carry addresses and IPs)
    let first = lower.split('\n').next().unwrap_or("");
    const MAIL: [&str; 13] = ["delivered-to:", "received:", "return-path:", "x-", "to:", "subject:", "date:", "message-id:", "content-type:", "reply-to:", "cc:", "bcc:", "sender:"];
    MAIL.iter().any(|h| first.starts_with(h))
}

fn text(d: &[u8]) -> Result<Cleaned, StripError> {
    if d.is_empty() { return Err(StripError::Unsupported); }
    let s = std::str::from_utf8(d).map_err(|_| StripError::Malformed("text", "not UTF-8"))?;
    if d.contains(&0) || looks_structured(s) { return Err(StripError::StructuredText); }
    let mut out = zeroize::Zeroizing::new(String::with_capacity(s.len()));
    let (mut removed, mut run) = (0usize, 0usize);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let c = if c == '\r' { if chars.peek() == Some(&'\n') { continue } else { '\n' } } else { c };
        let combining = sine_loco_core::text::is_combining(c);
        if sine_loco_core::text::is_unsafe_char(c) && c != '\n' && c != '\t' { removed += 1; continue; } // removed characters do NOT reset the run
        if combining { run += 1; if run > sine_loco_core::text::MAX_COMBINING_RUN { removed += 1; continue; } } else { run = 0; }
        out.push(c);
    }
    // a file made ONLY of removable characters would be sent as an empty file that the receiver's own cleaning refuses (found by fuzzing)
    if out.is_empty() { return Err(StripError::Unsupported); }
    // the OUTPUT must not look like a structured document either (a leading invisible character used to hide it)
    if looks_structured(&out) { return Err(StripError::StructuredText); }
    let mut report = vec!["plain text: ONLY invisible/control characters are removed; any document metadata inside the text is NOT understood".to_string()];
    if removed > 0 { report.push(format!("control/invisible/bidi/format characters: {removed} removed")); }
    Ok(Cleaned { format: Format::Text, data: std::mem::take(&mut *out).into_bytes(), report })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(d: &[u8]) -> Result<Cleaned, StripError> { super::clean(d, Mode::Auto) }
    fn text_clean(d: &[u8]) -> Result<Cleaned, StripError> { super::clean(d, Mode::PlainText) }

    fn seg(m: u8, body: &[u8]) -> Vec<u8> { let mut v = vec![0xFF, m]; v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes()); v.extend_from_slice(body); v }

    fn jpeg_with_metadata() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE1, b"Exif\0\0GPS 52.5N 13.4E Canon EOS thumbnail"));
        v.extend(seg(0xE0, b"JFIF\0"));
        v.extend(seg(0xFE, b"secret comment"));
        v.extend(seg(0xED, b"Photoshop 3.0 author"));
        v.extend(seg(0xDB, &[0; 65]));
        v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
        v.extend(seg(0xC4, &[0; 17]));
        v.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v.extend_from_slice(b"TRAILING-SECRET");
        v
    }

    #[test]
    fn jpeg_metadata_is_dropped_and_image_data_kept() {
        let c = clean(&jpeg_with_metadata()).unwrap();
        assert_eq!(c.format, Format::Jpeg);
        for needle in [&b"Exif"[..], b"GPS", b"Canon", b"secret comment", b"Photoshop", b"JFIF", b"TRAILING"] {
            assert!(!c.data.windows(needle.len()).any(|w| w == needle), "{:?} survived", String::from_utf8_lossy(needle));
        }
        assert!(c.data.windows(7).any(|w| w == [0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]), "scan data lost");
        assert!(c.data.ends_with(&[0xFF, 0xD9]));
        assert!(c.report.iter().any(|l| l.contains("APP1")) && c.report.iter().any(|l| l.contains("comment")) && c.report.iter().any(|l| l.contains("after end")));
        // idempotent
        assert_eq!(clean(&c.data).unwrap().data, c.data);
        assert!(clean(&c.data).unwrap().report.is_empty());
    }

    #[test]
    fn jpeg_malformed_is_refused() {
        let good = jpeg_with_metadata();
        assert!(clean(&good[..good.len() - 20]).is_err(), "truncated");
        let mut bad = good.clone(); bad[4] = 0xFF; bad[5] = 0xFF; // absurd segment length
        assert!(clean(&bad).is_err());
        assert!(clean(&[0xFF, 0xD8, 0xFF, 0xD9]).is_err(), "no image data");
    }

    /// A valid zlib stream (stored block) of the 2 raw bytes a 1x1 8-bit image needs.
    fn idat2() -> Vec<u8> { vec![0x78, 0x01, 0x01, 2, 0, 0xFD, 0xFF, 0, 0, 0x00, 0x02, 0x00, 0x01] }

    fn unhex(s: &str) -> Vec<u8> { (0..s.trim().len() / 2).map(|i| u8::from_str_radix(&s.trim()[2 * i..2 * i + 2], 16).unwrap()).collect() }

    fn png64(idat: &[u8]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 64, 0, 0, 0, 64, 8, 0, 0, 0, 0]));
        v.extend(chunk(b"IDAT", idat)); v.extend(chunk(b"IEND", &[])); v
    }

    #[test]
    fn zlib_streams_are_validated_exactly_real_dynamic_and_fixed_huffman() {
        for f in [include_str!("../testdata/zlib_dynamic_64x64_gray.hex"), include_str!("../testdata/zlib_fixed_64x64_gray.hex")] {
            let z = unhex(f);
            let png = png64(&z);
            let c = clean(&png).expect("a real encoder's output must be accepted");
            assert_eq!(c.data, png);
            // polyglot tail after the stream inside the IDAT
            let mut tail = z.clone(); tail.extend_from_slice(b"PK\x05\x06 hidden archive");
            assert!(clean(&png64(&tail)).is_err(), "bytes after the zlib stream");
            // truncated stream, flipped data bit (adler/structure), wrong header
            assert!(clean(&png64(&z[..z.len() - 3])).is_err());
            let mut flip = z.clone(); let m = flip.len() / 2; flip[m] ^= 0x10;
            assert!(clean(&png64(&flip)).is_err(), "corrupted stream");
            let mut hdr = z.clone(); hdr[0] = 0x79; assert!(clean(&png64(&hdr)).is_err());
        }
        // wrong decompressed size for the declared dimensions
        let mut small = b"\x89PNG\r\n\x1a\n".to_vec();
        small.extend(chunk(b"IHDR", &[0, 0, 0, 8, 0, 0, 0, 8, 8, 0, 0, 0, 0])); small.extend(chunk(b"IDAT", &unhex(include_str!("../testdata/zlib_fixed_64x64_gray.hex")))); small.extend(chunk(b"IEND", &[]));
        assert!(clean(&small).is_err(), "stream produces more data than IHDR allows");
        // decompression bomb: a tiny stream claiming a huge image is bounded by `expect`, never allocates
        let mut big = b"\x89PNG\r\n\x1a\n".to_vec();
        big.extend(chunk(b"IHDR", &[0x7F, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 16, 6, 0, 0, 0])); big.extend(chunk(b"IDAT", &idat2())); big.extend(chunk(b"IEND", &[]));
        assert!(clean(&big).is_err());
    }

    fn chunk(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(ty); v.extend_from_slice(body);
        let mut c = ty.to_vec(); c.extend_from_slice(body);
        v.extend_from_slice(&crc32(&c).to_be_bytes()); v
    }

    fn png_with_metadata() -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        v.extend(chunk(b"tEXt", b"Author\0Jane Doe"));
        v.extend(chunk(b"eXIf", b"GPS-DATA"));
        v.extend(chunk(b"tIME", &[7, 230, 1, 1, 0, 0, 0]));
        v.extend(chunk(b"prVt", b"private stuff"));
        v.extend(chunk(b"IDAT", &idat2()));
        v.extend(chunk(b"IEND", &[]));
        v.extend_from_slice(b"TRAILING-SECRET");
        v
    }

    #[test]
    fn png_ancillary_chunks_and_trailer_are_dropped() {
        let c = clean(&png_with_metadata()).unwrap();
        for needle in [&b"Jane"[..], b"GPS-DATA", b"tIME", b"private", b"TRAILING"] {
            assert!(!c.data.windows(needle.len()).any(|w| w == needle), "{:?} survived", String::from_utf8_lossy(needle));
        }
        assert!(c.data.windows(4).any(|w| w == b"IDAT"));
        assert_eq!(clean(&c.data).unwrap().data, c.data);
        assert!(c.report.len() >= 4);
    }

    #[test]
    fn png_bad_crc_or_order_is_refused() {
        let mut p2 = png_with_metadata(); p2[20] ^= 1; // inside IHDR
        assert!(clean(&p2).is_err());
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IDAT", &[1, 2, 3])); v.extend(chunk(b"IEND", &[]));
        assert!(clean(&v).is_err(), "IDAT before IHDR");
    }

    #[test]
    fn auto_mode_refuses_everything_that_is_not_jpeg_or_png() {
        assert_eq!(clean(b"%PDF-1.7\x00\x01\x02").unwrap_err(), StripError::Unsupported);
        assert_eq!(clean(b"PK\x03\x04\xff\xfe").unwrap_err(), StripError::Unsupported);
        assert_eq!(clean(&[]).unwrap_err(), StripError::Unsupported);
        // UTF-8 documents are NOT silently treated as text any more (review 9 H1)
        for doc in [&b"{\\rtf1{\\info{\\author Jane Doe}}}"[..], b"<svg xmlns='x'><metadata>jdoe</metadata></svg>", b"%!PS-Adobe-3.0\n%%For: jdoe", b"<?xml version='1.0'?><gpx/>", b"%PDF-1.4 /Author (jdoe)"] {
            assert_eq!(clean(doc).unwrap_err(), StripError::Unsupported);
            assert!(matches!(text_clean(doc), Err(StripError::StructuredText)), "{:?}", String::from_utf8_lossy(doc));
        }
        assert_eq!(clean(&vec![b'a'; MAX_INPUT + 1]).unwrap_err(), StripError::TooLarge);
    }

    #[test]
    fn plain_text_mode_removes_every_invisible_channel() {
        let c = text_clean("hi\u{202E}there\r\nline\u{0007}\u{200B}\rend".as_bytes()).unwrap();
        assert_eq!(std::str::from_utf8(&c.data).unwrap(), "hithere\nline\nend");
        assert!(c.report[0].contains("NOT understood"), "the UI must be told what plain text mode does not do");
        // tag characters (invisible payload), variation selectors, soft hyphen, fillers, noncharacters, private use
        let hidden: String = "Public statement.".chars().chain("SOURCE=alice".chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()))
            .chain(['\u{00AD}', '\u{FE0F}', '\u{E0100}', '\u{2028}', '\u{180E}', '\u{3164}', '\u{115F}', '\u{F0000}', '\u{061C}', '\u{FFF9}', '\u{034F}', '\u{FFFF}']).collect();
        let c = text_clean(hidden.as_bytes()).unwrap();
        assert_eq!(std::str::from_utf8(&c.data).unwrap(), "Public statement.");
        // stacked combining marks are capped
        let zalgo = format!("a{}", "\u{0301}".repeat(50));
        assert!(text_clean(zalgo.as_bytes()).unwrap().data.len() < 20);
    }

    #[test]
    fn jpeg_structural_segments_cannot_carry_extra_bytes() {
        let base = |dqt: &[u8], dht: &[u8], sos: &[u8]| {
            let mut v = vec![0xFF, 0xD8];
            v.extend(seg(0xDB, dqt)); v.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])); v.extend(seg(0xC4, dht)); v.extend(seg(0xDA, sos));
            v.extend_from_slice(&[0x11, 0xFF, 0xD9]); v
        };
        assert!(clean(&base(&[0; 65], &[0; 17], &[1, 1, 0, 0, 0x3F, 0])).is_ok());
        let mut fat_dqt = vec![0u8; 65]; fat_dqt.extend_from_slice(b"GPS 52.5200N owner=jdoe");
        assert!(clean(&base(&fat_dqt, &[0; 17], &[1, 1, 0, 0, 0x3F, 0])).is_err(), "padded DQT");
        let mut fat_dht = vec![0u8; 17]; fat_dht.extend_from_slice(b"hidden");
        assert!(clean(&base(&[0; 65], &fat_dht, &[1, 1, 0, 0, 0x3F, 0])).is_err(), "padded DHT");
        assert!(clean(&base(&[0; 65], &[0; 17], &[1, 1, 0, 0, 0x3F, 0, 9, 9])).is_err(), "padded SOS header");
        // arithmetic coding and DAC are refused rather than copied blindly
        let mut v = vec![0xFF, 0xD8]; v.extend(seg(0xCC, b"anything"));
        assert_eq!(clean(&v).unwrap_err(), StripError::Unsupported);
    }

    #[test]
    fn png_report_is_bounded_even_with_hostile_chunk_names() {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        for a in b'a'..=b'z' { for b in b'a'..=b'z' { v.extend(chunk(&[a, b, b'x', b'y'], b"")); } }
        v.extend(chunk(b"IDAT", &idat2())); v.extend(chunk(b"IEND", &[]));
        let c = clean(&v).unwrap();
        assert!(c.report.len() <= MAX_REPORT && c.report.iter().any(|l| l.contains("676")), "{:?}", c.report);
    }

    #[test]
    fn covert_channels_in_palette_transparency_and_tables_are_closed() {
        // grayscale image with a 256-byte "tRNS" and a 768-byte "PLTE": both dropped, not copied
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        v.extend(chunk(b"PLTE", &[0x41; 768])); v.extend(chunk(b"tRNS", &[0x42; 256]));
        v.extend(chunk(b"IDAT", &idat2())); v.extend(chunk(b"IEND", &[]));
        let c = clean(&v).unwrap();
        assert!(!c.data.windows(4).any(|w| w == [0x41; 4] || w == [0x42; 4]), "payload survived");
        // the legal 2-byte grey tRNS is kept
        let mut ok = b"\x89PNG\r\n\x1a\n".to_vec();
        ok.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0])); ok.extend(chunk(b"tRNS", &[0, 7])); ok.extend(chunk(b"IDAT", &idat2())); ok.extend(chunk(b"IEND", &[]));
        assert_eq!(clean(&ok).unwrap().data, ok);
        // JPEG: 100 redefinitions of an unused table are refused
        let mut j = vec![0xFF, 0xD8];
        for _ in 0..100 { j.extend(seg(0xDB, &[3; 1].iter().chain([0x42u8; 64].iter()).copied().collect::<Vec<u8>>())); }
        j.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])); j.extend(seg(0xC4, &[0; 17])); j.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0])); j.extend_from_slice(&[0x11, 0xFF, 0xD9]);
        assert!(clean(&j).is_err());
    }

    #[test]
    fn text_with_nothing_left_after_cleaning_is_refused_not_sent_as_an_empty_file() {
        for d in [&b"\x02\x02"[..], "\u{200B}\u{202E}".as_bytes(), b"\x1b[2J".as_slice()].iter().take(2) {
            assert_eq!(text_clean(d).unwrap_err(), StripError::Unsupported, "{d:?}");
        }
        assert!(text_clean(b"a\x02").is_ok());
    }

    #[test]
    fn text_cleaning_is_idempotent_safe_and_cannot_hide_a_document_or_stacked_marks() {
        assert!(text_clean("\u{200B}{\\rtf1{\\info{\\author Jane}}}".as_bytes()).is_err(), "leading invisible char must not hide an RTF");
        assert!(text_clean("\u{202E}<svg><metadata>owner=jdoe</metadata></svg>".as_bytes()).is_err());
        let sneaky = format!("a{}", "\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{200B}".repeat(20));
        let out = text_clean(sneaky.as_bytes()).unwrap().data;
        assert!(String::from_utf8(out.clone()).unwrap().chars().filter(|c| sine_loco_core::text::is_combining(*c)).count() <= sine_loco_core::text::MAX_COMBINING_RUN);
        assert_eq!(text_clean(&out).unwrap().data, out, "idempotent");
    }

    #[test]
    fn structured_text_check_skips_every_kind_of_blank_and_catches_mail_headers() {
        for doc in ["\u{00A0}{\\rtf1{\\info{\\author Jane Doe}}}", "\u{3000}<html><meta name=author content=x>", "\u{2000}<svg><metadata>x</metadata></svg>", "\u{0301}{\\rtf1}", "\u{00A0}%!PS-Adobe\n%%Creator: x",
                    "Delivered-To: me@example.org\nX-Originating-IP: [203.0.113.7]\nSubject: hi\n\nbody", "Received: from mail.example.org by x\n"] {
            assert!(text_clean(doc.as_bytes()).is_err(), "{doc:?}");
        }
        assert!(text_clean(b"Dear all,\nthe meeting is at noon.\n").is_ok());
    }

    #[test]
    fn many_empty_deflate_blocks_are_refused_quickly() {
        // 25_000 empty fixed-Huffman blocks (10 bits each), then a final stored block: valid zlib, hostile work factor
        let mut bits: Vec<bool> = vec![];
        let push = |bits: &mut Vec<bool>, v: u32, n: u32| for i in 0..n { bits.push(v >> i & 1 == 1) };
        for _ in 0..25_000 { push(&mut bits, 0, 1); push(&mut bits, 1, 2); push(&mut bits, 0, 7); }
        push(&mut bits, 1, 1); push(&mut bits, 0, 2);
        while !bits.len().is_multiple_of(8) { bits.push(false); }
        let mut z = vec![0x78, 0x01];
        for c in bits.chunks(8) { z.push(c.iter().enumerate().fold(0u8, |a, (i, &b)| a | (b as u8) << i)); }
        z.extend_from_slice(&[2, 0, 0xFD, 0xFF, 0, 0, 0x00, 0x02, 0x00, 0x01]);
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0])); v.extend(chunk(b"IDAT", &z)); v.extend(chunk(b"IEND", &[]));
        let t = std::time::Instant::now();
        assert!(clean(&v).is_err(), "block-count cap");
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    /// Deterministic mutation fuzzing: hostile input may be refused but must NEVER panic (panic = abort kills the whole app).
    #[test]
    fn mutated_inputs_never_panic() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut rnd = move || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
        let bases = [jpeg_with_metadata(), png_with_metadata(), png64(&unhex(include_str!("../testdata/zlib_dynamic_64x64_gray.hex"))), png64(&unhex(include_str!("../testdata/zlib_fixed_64x64_gray.hex")))];
        for base in &bases {
            for _ in 0..4000 {
                let mut v = base.clone();
                for _ in 0..(1 + rnd() % 4) {
                    let i = (rnd() as usize) % v.len();
                    match rnd() % 4 { 0 => v[i] ^= 1 << (rnd() % 8), 1 => v[i] = rnd() as u8, 2 => { v.truncate(i.max(1)); } _ => { let b = rnd() as u8; v.insert(i, b); } }
                }
                let _ = super::clean(&v, Mode::Auto);
                let _ = super::clean(&v, Mode::PlainText);
            }
        }
        // CRC-fixing mutator: mutate the zlib payload itself so the mutants actually reach the deflate validator
        for f in [include_str!("../testdata/zlib_dynamic_64x64_gray.hex"), include_str!("../testdata/zlib_fixed_64x64_gray.hex")] {
            let z = unhex(f);
            for _ in 0..6000 {
                let mut m = z.clone();
                for _ in 0..(1 + rnd() % 3) { let i = (rnd() as usize) % m.len(); m[i] ^= 1 << (rnd() % 8); }
                let _ = super::clean(&png64(&m), Mode::Auto);
            }
        }
    }

    #[test]
    fn png_palette_and_header_values_are_validated() {
        let mk = |plte: &[u8]| { let mut v = b"\x89PNG\r\n\x1a\n".to_vec(); v.extend(chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 3, 0, 0, 0])); v.extend(chunk(b"PLTE", plte)); v.extend(chunk(b"IDAT", &idat2())); v.extend(chunk(b"IEND", &[])); v };
        assert!(clean(&mk(&[1, 2, 3, 4, 5, 6])).is_ok());
        assert!(clean(&mk(&[1, 2, 3, 4])).is_err(), "PLTE length not a multiple of 3 (hidden bytes)");
        assert!(clean(&mk(&[])).is_err());
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec(); v.extend(chunk(b"IHDR", &[0, 0, 0, 0, 0, 0, 0, 1, 8, 0, 0, 0, 0]));
        assert!(clean(&v).is_err(), "zero width");
    }
}
