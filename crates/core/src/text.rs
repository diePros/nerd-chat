//! Text hygiene for everything a PEER controls (messages, contact names, filenames later).
//! No terminal control, no invisible/format/bidi characters, no private-use or noncharacters, bounded combining marks.
use zeroize::Zeroizing;

/// Characters that must never reach a screen or a name: control (Cc), format/invisible (Cf), line/paragraph separators
/// (Zl/Zp), private use (Co), noncharacters, blank fillers, variation selectors and tag characters.
pub fn is_unsafe_char(c: char) -> bool {
    if c.is_control() { return true; }
    let u = c as u32;
    matches!(u,
        0x00AD | 0x034F | 0x061C | 0x06DD | 0x070F | 0x08E2 | 0x115F | 0x1160 | 0x17B4 | 0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0
        | 0xFFF0..=0xFFFB | 0xFFFE | 0xFFFF | 0xFDD0..=0xFDEF | 0xE000..=0xF8FF | 0x110BD | 0x110CD
        | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF | 0xF0000..=0x10FFFF)
}

/// Common combining-mark blocks (stacking them can overflow a layout or hide neighbours).
fn is_combining(c: char) -> bool {
    matches!(c as u32, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F)
}

pub const MAX_COMBINING_RUN: usize = 4;

/// Replace unsafe characters by '?' and drop combining marks beyond `MAX_COMBINING_RUN` in a row.
pub fn sanitize(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut run = 0;
    for c in text.chars() {
        if is_combining(c) { run += 1; if run > MAX_COMBINING_RUN { continue; } } else { run = 0; }
        out.push(if is_unsafe_char(c) { '?' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_characters_are_replaced() {
        for c in ['\x1b', '\x07', '\u{0085}', '\u{061C}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{200B}', '\u{FEFF}', '\u{00AD}',
                  '\u{180E}', '\u{3164}', '\u{115F}', '\u{FE0F}', '\u{E0041}', '\u{E000}', '\u{F0000}', '\u{FFFF}', '\u{FDD0}', '\u{206A}', '\u{FFF9}'] {
            assert!(is_unsafe_char(c), "U+{:04X}", c as u32);
            assert_eq!(&*sanitize(&format!("a{c}b")), "a?b", "U+{:04X}", c as u32);
        }
        for c in ['a', 'Z', 'ü', '€', '😀', '漢', 'א', ' ', '\u{0301}'] { assert!(!is_unsafe_char(c), "{c:?}"); }
        assert_eq!(&*sanitize("héllo 漢字 😀 שלום"), "héllo 漢字 😀 שלום");
    }

    #[test]
    fn stacked_combining_marks_are_capped() {
        let zalgo = format!("a{}b", "\u{0301}".repeat(50));
        let s = sanitize(&zalgo);
        assert_eq!(s.chars().filter(|c| is_combining(*c)).count(), MAX_COMBINING_RUN);
        assert!(s.starts_with('a') && s.ends_with('b'));
        // a normal accent after each of many letters is untouched
        assert_eq!(&*sanitize("é́é"), &*sanitize("é́é"));
    }
}
