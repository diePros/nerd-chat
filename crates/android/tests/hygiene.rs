//! The bridge is the one place where the exported JNI symbols need `unsafe_code` to be allowed. Keep it to exactly that.
use std::fs;

fn src(f: &str) -> String { fs::read_to_string(format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap() }

/// Every .rs file under src/, recursively (a submodule of `ffi` would inherit its `allow(unsafe_code)`): (relative path, content).
fn all_sources() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, String)>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() { walk(&p, base, out); } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((p.strip_prefix(base).unwrap().display().to_string(), fs::read_to_string(&p).unwrap()));
            }
        }
    }
    let base = std::path::PathBuf::from(format!("{}/src", env!("CARGO_MANIFEST_DIR")));
    let mut v = Vec::new(); walk(&base, &base, &mut v); v
}

#[test]
fn the_whole_source_tree_is_scanned_not_a_fixed_list() {
    let files = all_sources();
    assert!(files.iter().any(|(n, _)| n == "ffi.rs") && files.len() >= 5, "{:?}", files.iter().map(|f| &f.0).collect::<Vec<_>>());
    for (name, s) in &files {
        let code = s.lines().filter(|l| !l.trim_start().starts_with("//"));
        let code: Vec<&str> = code.collect();
        assert!(!code.iter().any(|l| l.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "unsafe")), "{name}: no `unsafe` block, fn or impl");
        assert!(!code.iter().any(|l| l.contains("export_name") || l.contains("link_section")), "{name}: no other way to export a symbol");
        if name != "ffi.rs" { assert!(!s.contains("allow(unsafe_code)"), "{name} must stay fully safe"); }
    }
}

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
fn exactly_four_jni_symbols_are_exported() {
    let s = src("ffi.rs");
    let code: Vec<&str> = s.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
    assert_eq!(code.iter().filter(|l| l.trim() == "#[no_mangle]").count(), 4);
    assert!(s.contains("Java_app_sineloco_model_NativeBridge_nInit") && s.contains("Java_app_sineloco_model_NativeBridge_nCall"));
    // nSendFile / nFileBytes: binary photo data cannot travel through the text argument of nCall
    assert!(s.contains("Java_app_sineloco_model_NativeBridge_nSendFile") && s.contains("Java_app_sineloco_model_NativeBridge_nFileBytes"));
}
