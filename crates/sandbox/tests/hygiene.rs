//! "Exactly one unsafe block" is a project promise, but `#![deny(unsafe_code)]` + `#[allow]` cannot enforce it (forbid cannot be
//! overridden, so it cannot be used here). This test does.
const SRC: &str = include_str!("../src/lib.rs");

fn code_lines() -> Vec<&'static str> { SRC.lines().filter(|l| !l.trim_start().starts_with("//")).collect() }

#[test]
fn exactly_one_unsafe_block_and_one_allow() {
    let code = code_lines().join("\n");
    assert_eq!(code.matches("unsafe {").count(), 1, "the crate must contain exactly ONE unsafe block");
    assert_eq!(code.matches("allow(unsafe_code)").count(), 1);
    assert_eq!(code.matches("deny(unsafe_code)").count(), 1);
    for forbidden in ["unsafe fn", "unsafe impl", "unsafe trait", "asm!", "extern \"", "static mut", "transmute", "from_raw", "get_unchecked", "unsafe extern"] {
        assert!(!code.contains(forbidden), "`{forbidden}` must not appear in the sandbox crate");
    }
}

#[test]
fn the_unsafe_block_is_documented_and_calls_only_prctl() {
    let lines = code_lines();
    let i = lines.iter().position(|l| l.contains("unsafe {")).unwrap();
    assert!(lines[i].contains("libc::prctl("), "the unsafe block must be the prctl call");
    // a SAFETY comment must directly precede it in the source
    let at = SRC.lines().position(|l| l.contains("unsafe {")).unwrap();
    assert!(SRC.lines().nth(at - 1).unwrap().trim_start().starts_with("// SAFETY:") || SRC.lines().nth(at - 2).unwrap().trim_start().starts_with("// SAFETY:"), "missing SAFETY comment");
}
