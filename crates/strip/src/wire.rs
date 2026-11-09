//! Wire format between the app and its sandboxed cleaning helper (a child process with hard resource limits).
//! The helper runs our parsers over hostile files, so its OUTPUT is parsed as strictly as any peer input here:
//! exact lengths, hard caps, control characters in text neutralised, no trailing bytes.
use crate::{Cleaned, Format, Mode, StripError, MAX_INPUT};

const MAX_LINE: usize = 200;
const MAX_LINES: usize = 16;

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let b = &b[..b.len().min(MAX_LINE)];
    // never cut a UTF-8 char in half
    let n = (0..=b.len()).rev().find(|&n| std::str::from_utf8(&b[..n]).is_ok()).unwrap_or(0);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&b[..n]);
}

/// `mode(1) | len(4) | data`
pub fn encode_request(mode: Mode, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + data.len());
    v.push(match mode { Mode::Auto => 0, Mode::PlainText => 1 });
    v.extend_from_slice(&(data.len() as u32).to_be_bytes());
    v.extend_from_slice(data);
    v
}

pub fn decode_request(b: &[u8]) -> Option<(Mode, &[u8])> {
    let (&m, rest) = b.split_first()?;
    let mode = match m { 0 => Mode::Auto, 1 => Mode::PlainText, _ => return None };
    let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    let data = rest.get(4..)?;
    (len == data.len() && len <= MAX_INPUT).then_some((mode, data))
}

/// ok: `0 | format(1) | nlines(1) | (len(2) line)* | len(4) | data`; error: `1 | code(1) | len(2) text`
pub fn encode_response(r: &Result<Cleaned, StripError>) -> Vec<u8> {
    let mut v = Vec::new();
    match r {
        Ok(c) => {
            v.push(0);
            v.push(match c.format { Format::Jpeg => 0, Format::Png => 1, Format::Text => 2 });
            let lines = &c.report[..c.report.len().min(MAX_LINES)];
            v.push(lines.len() as u8);
            for l in lines { put_str(&mut v, l); }
            v.extend_from_slice(&(c.data.len() as u32).to_be_bytes());
            v.extend_from_slice(&c.data);
        }
        Err(e) => {
            v.push(1);
            v.push(match e { StripError::TooLarge => 0, StripError::Unsupported => 1, StripError::StructuredText => 2, _ => 3 });
            put_str(&mut v, &e.to_string());
        }
    }
    v
}

fn garbage() -> StripError { StripError::Refused("the cleaning helper returned an invalid answer".into()) }

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> { if self.0.len() < n { return None; } let (a, b) = self.0.split_at(n); self.0 = b; Some(a) }
    fn u8(&mut self) -> Option<u8> { self.take(1).map(|b| b[0]) }
    fn u16(&mut self) -> Option<usize> { self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize) }
    fn line(&mut self) -> Option<String> {
        let n = self.u16()?;
        if n > MAX_LINE { return None; }
        let s = std::str::from_utf8(self.take(n)?).ok()?;
        Some(s.chars().map(|c| if c.is_control() || sine_loco_core::text::is_unsafe_char(c) { '?' } else { c }).collect())
    }
}

/// Strict decoder for the helper's answer (it is untrusted output of a parser that has just chewed on a hostile file).
pub fn decode_response(b: &[u8]) -> Result<Cleaned, StripError> {
    let mut r = R(b);
    let res = (|| -> Option<Result<Cleaned, StripError>> {
        match r.u8()? {
            0 => {
                let format = match r.u8()? { 0 => Format::Jpeg, 1 => Format::Png, 2 => Format::Text, _ => return None };
                let n = r.u8()? as usize;
                if n > MAX_LINES { return None; }
                let mut report = Vec::with_capacity(n);
                for _ in 0..n { report.push(r.line()?); }
                let dl = u32::from_be_bytes(r.take(4)?.try_into().ok()?) as usize;
                if dl > MAX_INPUT { return None; }
                let data = r.take(dl)?.to_vec();
                Some(Ok(Cleaned { format, data, report }))
            }
            1 => {
                let code = r.u8()?;
                let text = r.line()?;
                Some(Err(match code { 0 => StripError::TooLarge, 1 => StripError::Unsupported, 2 => StripError::StructuredText, 3 => StripError::Refused(text), _ => return None }))
            }
            _ => None,
        }
    })();
    match res {
        Some(x) if r.0.is_empty() => x,
        Some(Ok(mut c)) => { zeroize::Zeroize::zeroize(&mut c.data); Err(garbage()) } // rejected for trailing bytes: do not leave the copy
        _ => Err(garbage()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_response_roundtrip() {
        let req = encode_request(Mode::PlainText, b"hello");
        let (m, d) = decode_request(&req).unwrap();
        assert_eq!((m, d), (Mode::PlainText, &b"hello"[..]));
        let c = Cleaned { format: Format::Png, data: vec![1, 2, 3], report: vec!["removed 2 chunks".into()] };
        let back = decode_response(&encode_response(&Ok(c))).unwrap();
        assert_eq!((back.format, back.data, back.report), (Format::Png, vec![1, 2, 3], vec!["removed 2 chunks".to_string()]));
        assert!(matches!(decode_response(&encode_response(&Err(StripError::Unsupported))), Err(StripError::Unsupported)));
        assert!(matches!(decode_response(&encode_response(&Err(StripError::Malformed("PNG", "bad IHDR")))), Err(StripError::Refused(t)) if t.contains("bad IHDR")));
    }

    #[test]
    fn a_hostile_helper_answer_is_rejected_or_neutralised() {
        let c = Cleaned { format: Format::Jpeg, data: vec![9; 10], report: vec!["x\x1b[2Jy\u{202E}".into()] };
        let ok = decode_response(&encode_response(&Ok(c))).unwrap();
        assert_eq!(ok.report[0], "x?[2Jy?", "terminal escapes in the helper's report must be neutralised");
        let good = encode_response(&Ok(Cleaned { format: Format::Text, data: vec![1; 4], report: vec![] }));
        for cut in 0..good.len() { assert!(decode_response(&good[..cut]).is_err(), "truncated at {cut}"); }
        let mut t = good.clone(); t.push(0); assert!(decode_response(&t).is_err(), "trailing bytes");
        let mut t = good.clone(); t[1] = 9; assert!(decode_response(&t).is_err(), "unknown format");
        let mut t = good.clone(); t[0] = 7; assert!(decode_response(&t).is_err(), "unknown status");
        let mut huge = vec![0u8, 0, 0]; huge.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(decode_response(&huge).is_err(), "oversized length");
        let mut many = vec![0u8, 0, 200]; many.extend_from_slice(&[0, 0]);
        assert!(decode_response(&many).is_err(), "too many report lines");
        assert!(decode_request(&[0, 0, 0, 0, 9, 1]).is_none(), "request length mismatch");
    }
}
