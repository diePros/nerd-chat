//! Metadata stripping by ALLOWLIST: we re-emit only the structural parts of a file that are needed to display it and
//! drop everything else (unknown segments, comments, EXIF/XMP/ICC, thumbnails, trailing data). Formats are recognised
//! by content (magic bytes), never by file name. Unknown formats are refused.
//!
//! Honest limits: pixel/compressed image data is copied unchanged (information hidden inside the entropy-coded data
//! or visible in the picture itself is NOT removed); removing EXIF orientation / colour profiles can change how an
//! image is displayed. Parsers here are small, pure Rust and allocation-bounded (`MAX_INPUT`).
#![forbid(unsafe_code)]

pub const MAX_INPUT: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StripError {
    #[error("file too large (max {MAX_INPUT} bytes)")]
    TooLarge,
    #[error("unsupported or unrecognised format (refused: it cannot be cleaned)")]
    Unsupported,
    #[error("malformed {0} file: {1}")]
    Malformed(&'static str, &'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format { Jpeg, Png, Text }

#[derive(Debug)]
pub struct Cleaned {
    pub format: Format,
    pub data: Vec<u8>,
    /// Human-readable before/after report, one line per removed item kind.
    pub report: Vec<String>,
}

pub fn sniff(d: &[u8]) -> Option<Format> {
    if d.starts_with(&[0xFF, 0xD8, 0xFF]) { Some(Format::Jpeg) }
    else if d.starts_with(b"\x89PNG\r\n\x1a\n") { Some(Format::Png) }
    else if std::str::from_utf8(d).is_ok() && !d.is_empty() && !d.contains(&0) { Some(Format::Text) }
    else { None }
}

pub fn clean(d: &[u8]) -> Result<Cleaned, StripError> {
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
    match sniff(d).ok_or(StripError::Unsupported)? {
        Format::Jpeg => jpeg(d),
        Format::Png => png(d),
        Format::Text => text(d),
    }
}

fn note(report: &mut Vec<String>, what: String, n: usize, bytes: usize) {
    report.push(format!("{what}: {n} item(s), {bytes} bytes removed"));
}

// ---------------- JPEG ----------------
fn jpeg(d: &[u8]) -> Result<Cleaned, StripError> {
    const M: &str = "JPEG";
    let mut out = Vec::with_capacity(d.len());
    let mut dropped: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut i = 2;
    let mut seen_sof = false;
    let mut seen_scan = false;
    loop {
        // find the next marker (tolerate fill bytes 0xFF)
        if i >= d.len() { return Err(StripError::Malformed(M, "missing EOI")); }
        if d[i] != 0xFF { return Err(StripError::Malformed(M, "expected marker")); }
        while i < d.len() && d[i] == 0xFF { i += 1; }
        if i >= d.len() { return Err(StripError::Malformed(M, "truncated")); }
        let m = d[i]; i += 1;
        match m {
            0xD9 => { // EOI
                if !seen_scan { return Err(StripError::Malformed(M, "no image data")); }
                out.extend_from_slice(&[0xFF, 0xD9]);
                if i < d.len() { dropped.entry("data after end of image".into()).or_default().1 += d.len() - i; }
                break;
            }
            0x00 | 0x01 | 0xD0..=0xD8 => return Err(StripError::Malformed(M, "unexpected standalone marker")),
            _ => {}
        }
        if i + 2 > d.len() { return Err(StripError::Malformed(M, "truncated segment")); }
        let len = u16::from_be_bytes([d[i], d[i + 1]]) as usize;
        if len < 2 || i + len > d.len() { return Err(StripError::Malformed(M, "bad segment length")); }
        let seg = &d[i..i + len];
        let is_sof = matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF);
        let keep = is_sof || matches!(m, 0xC4 | 0xCC | 0xDB | 0xDD | 0xDA | 0xDC);
        i += len;
        if keep {
            if is_sof { seen_sof = true; }
            out.extend_from_slice(&[0xFF, m]);
            out.extend_from_slice(seg);
            if m == 0xDA { // entropy-coded data up to the next real marker
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
            let name = match m { 0xE0..=0xEF => format!("application segment APP{} (EXIF/XMP/ICC/thumbnail/...)", m - 0xE0), 0xFE => "comment".into(), _ => format!("segment 0xFF{m:02X}") };
            let e = dropped.entry(name).or_default(); e.0 += 1; e.1 += len + 2;
        }
    }
    let mut report = vec![];
    for (k, (n, b)) in dropped { note(&mut report, k, n.max(1), b); }
    Ok(Cleaned { format: Format::Jpeg, data: out, report })
}

// ---------------- PNG ----------------
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (n, t) in table.iter_mut().enumerate() {
        let mut c = n as u32;
        for _ in 0..8 { c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 }; }
        *t = c;
    }
    let mut c = 0xFFFF_FFFFu32;
    for &b in data { c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8); }
    c ^ 0xFFFF_FFFF
}

fn png(d: &[u8]) -> Result<Cleaned, StripError> {
    const M: &str = "PNG";
    let mut out = d[..8].to_vec();
    let mut i = 8;
    let mut dropped: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    let (mut ihdr, mut idat, mut iend) = (false, false, false);
    while i < d.len() && !iend {
        if i + 12 > d.len() { return Err(StripError::Malformed(M, "truncated chunk")); }
        let len = u32::from_be_bytes(d[i..i + 4].try_into().unwrap()) as usize;
        if len > 0x7FFF_FFFF || i + 12 + len > d.len() { return Err(StripError::Malformed(M, "bad chunk length")); }
        let ty = &d[i + 4..i + 8];
        let crc = u32::from_be_bytes(d[i + 8 + len..i + 12 + len].try_into().unwrap());
        if crc32(&d[i + 4..i + 8 + len]) != crc { return Err(StripError::Malformed(M, "chunk CRC mismatch")); }
        if !ty.iter().all(u8::is_ascii_alphabetic) { return Err(StripError::Malformed(M, "bad chunk type")); }
        let whole = &d[i..i + 12 + len];
        match ty {
            b"IHDR" => { if ihdr || i != 8 || len != 13 { return Err(StripError::Malformed(M, "bad IHDR")); } ihdr = true; out.extend_from_slice(whole); }
            b"PLTE" | b"tRNS" => { if !ihdr || idat { return Err(StripError::Malformed(M, "chunk out of order")); } out.extend_from_slice(whole); }
            b"IDAT" => { if !ihdr { return Err(StripError::Malformed(M, "IDAT before IHDR")); } idat = true; out.extend_from_slice(whole); }
            b"IEND" => { if !idat || len != 0 { return Err(StripError::Malformed(M, "bad IEND")); } out.extend_from_slice(whole); iend = true; }
            _ => {
                let name = match ty {
                    b"tEXt" | b"zTXt" | b"iTXt" => "text chunk (author/comment/software/XMP)".to_string(),
                    b"eXIf" => "EXIF block".into(),
                    b"tIME" => "modification time".into(),
                    b"iCCP" => "ICC colour profile".into(),
                    _ => format!("chunk {}", String::from_utf8_lossy(ty)),
                };
                let e = dropped.entry(name).or_default(); e.0 += 1; e.1 += whole.len();
            }
        }
        i += 12 + len;
    }
    if !iend { return Err(StripError::Malformed(M, "missing IEND")); }
    if i < d.len() { dropped.entry("data after IEND".into()).or_default().1 += d.len() - i; }
    let mut report = vec![];
    for (k, (n, b)) in dropped { note(&mut report, k, n.max(1), b); }
    Ok(Cleaned { format: Format::Png, data: out, report })
}

// ---------------- plain text ----------------
fn text(d: &[u8]) -> Result<Cleaned, StripError> {
    let s = std::str::from_utf8(d).map_err(|_| StripError::Malformed("text", "not UTF-8"))?;
    let mut out = String::with_capacity(s.len());
    let mut removed = 0usize;
    for c in s.replace("\r\n", "\n").chars() {
        let bad = (c.is_control() && c != '\n' && c != '\t') || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E000}'..='\u{F8FF}');
        if bad { removed += 1 } else { out.push(c) }
    }
    let mut report = vec![];
    if removed > 0 { report.push(format!("control/invisible/bidi characters: {removed} removed")); }
    Ok(Cleaned { format: Format::Text, data: out.into_bytes(), report })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        v.extend(chunk(b"IDAT", &[0x78, 0x9C, 0x63, 0, 0, 0, 2, 0, 1]));
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
    fn unknown_formats_are_refused_and_text_is_sanitised() {
        assert_eq!(clean(b"%PDF-1.7\x00\x01\x02").unwrap_err(), StripError::Unsupported);
        assert_eq!(clean(b"PK\x03\x04\xff\xfe").unwrap_err(), StripError::Unsupported);
        assert_eq!(clean(&[]).unwrap_err(), StripError::Unsupported);
        let c = clean("hi\u{202E}there\r\nline\u{0007}\u{200B}".as_bytes()).unwrap();
        assert_eq!(std::str::from_utf8(&c.data).unwrap(), "hithere\nline");
        assert_eq!(clean(&vec![b'a'; MAX_INPUT + 1]).unwrap_err(), StripError::TooLarge);
    }
}
