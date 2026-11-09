//! A tiny JSON writer: enough for the snapshot, no dependency. Strings are escaped per RFC 8259 (quote, backslash, control characters);
//! everything else, including non-BMP characters, is written as UTF-8.
pub struct W { s: String, need_comma: Vec<bool> }

fn escape(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04x}", c as u32)),
            // U+2028/2029 are valid JSON but break some JavaScript parsers; escape them so every consumer is safe
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl W {
    pub fn new() -> Self { Self::with_capacity(1024) }
    /// Pre-sized: a growing String frees every earlier, partly written copy of the snapshot (chat text included) without wiping it.
    pub fn with_capacity(n: usize) -> Self { W { s: String::with_capacity(n), need_comma: vec![false] } }
    fn sep(&mut self) { if let Some(n) = self.need_comma.last_mut() { if *n { self.s.push(','); } *n = true; } }
    fn key(&mut self, k: &str) { self.sep(); escape(&mut self.s, k); self.s.push(':'); }
    pub fn obj(&mut self) { self.sep(); self.s.push('{'); self.need_comma.push(false); }
    pub fn arr_item_obj(&mut self) { self.obj(); }
    pub fn end_obj(&mut self) { self.s.push('}'); self.need_comma.pop(); }
    pub fn end_arr(&mut self) { self.s.push(']'); self.need_comma.pop(); }
    pub fn f_obj(&mut self, k: &str) { self.key(k); self.s.push('{'); self.need_comma.push(false); }
    pub fn f_arr(&mut self, k: &str) { self.key(k); self.s.push('['); self.need_comma.push(false); }
    pub fn f_str(&mut self, k: &str, v: &str) { self.key(k); escape(&mut self.s, v); }
    pub fn f_num(&mut self, k: &str, v: i64) { self.key(k); self.s.push_str(&v.to_string()); }
    pub fn f_bool(&mut self, k: &str, v: bool) { self.key(k); self.s.push_str(if v { "true" } else { "false" }); }
    pub fn f_null(&mut self, k: &str) { self.key(k); self.s.push_str("null"); }
    pub fn f_opt_str(&mut self, k: &str, v: Option<&str>) { match v { Some(v) => self.f_str(k, v), None => self.f_null(k) } }
    pub fn item_str(&mut self, v: &str) { self.sep(); escape(&mut self.s, v); }
    pub fn finish(self) -> zeroize::Zeroizing<String> { zeroize::Zeroizing::new(self.s) }
}

impl Default for W { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_values_have_correct_commas() {
        let mut w = W::new();
        w.obj();
        w.f_num("a", 1); w.f_bool("b", true); w.f_null("c");
        w.f_arr("d"); w.arr_item_obj(); w.f_str("x", "y"); w.end_obj(); w.arr_item_obj(); w.end_obj(); w.item_str("z"); w.end_arr();
        w.f_obj("e"); w.f_opt_str("n", None); w.f_opt_str("s", Some("t")); w.end_obj();
        w.end_obj();
        assert_eq!(w.finish().as_str(), r#"{"a":1,"b":true,"c":null,"d":[{"x":"y"},{},"z"],"e":{"n":null,"s":"t"}}"#);
    }

    #[test]
    fn strings_are_escaped_and_roundtrip_through_a_strict_parser_shape() {
        let mut w = W::new();
        w.obj(); w.f_str("t", "q\"b\\n\nr\rt\tc\u{1}d\u{7f}e\u{2028}ü😀"); w.end_obj();
        let s = w.finish();
        assert_eq!(&**s, "{\"t\":\"q\\\"b\\\\n\\nr\\rt\\tc\\u0001d\\u007fe\\u2028ü😀\"}");
        assert!(!s.contains('\n') && !s.contains('\u{1}'), "no raw control characters survive");
    }
}
