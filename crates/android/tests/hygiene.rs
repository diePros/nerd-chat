//! The bridge is the one place where the exported JNI symbols need `unsafe_code` to be allowed. Keep it to exactly that.
use std::fs;

fn src(f: &str) -> String { fs::read_to_string(format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap() }

#[test]
fn unsafe_is_allowed_in_exactly_one_module_and_no_unsafe_block_exists() {
    for f in ["lib.rs", "bridge.rs", "json.rs", "snapshot.rs", "ffi.rs"] {
        let s = src(f);
        // an `unsafe` keyword used as code (block, fn, impl), not the lint names `unsafe_code`
        let code_unsafe = s.lines().filter(|l| !l.trim_start().starts_with("//")).any(|l| l.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "unsafe"));
        assert!(!code_unsafe, "{f}: no `unsafe` block, fn or impl is allowed");
    }
    assert!(src("lib.rs").contains("#![deny(unsafe_code)]"));
    assert!(src("ffi.rs").contains("#![allow(unsafe_code)]"));
    for f in ["bridge.rs", "json.rs", "snapshot.rs"] { assert!(!src(f).contains("allow(unsafe_code)"), "{f} must stay fully safe"); }
}

#[test]
fn exactly_two_jni_symbols_are_exported() {
    let s = src("ffi.rs");
    let code: Vec<&str> = s.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
    assert_eq!(code.iter().filter(|l| l.trim() == "#[no_mangle]").count(), 2);
    assert!(s.contains("Java_app_nerdchat_model_NativeBridge_nInit") && s.contains("Java_app_nerdchat_model_NativeBridge_nCall"));
}
