//! The isolated-process library exports exactly one symbol, has no `unsafe` block, and links nothing but the stripper.
use std::fs;
#[test]
fn one_export_no_unsafe_block_and_no_other_dependency() {
    let root = env!("CARGO_MANIFEST_DIR");
    let s = fs::read_to_string(format!("{root}/src/lib.rs")).unwrap();
    let code: Vec<&str> = s.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
    assert_eq!(code.iter().filter(|l| l.trim() == "#[no_mangle]").count(), 1);
    assert!(!code.iter().any(|l| l.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "unsafe")), "no `unsafe` block, fn or impl");
    let toml = fs::read_to_string(format!("{root}/Cargo.toml")).unwrap();
    let deps = toml.split("[dependencies]").nth(1).unwrap().split("[dev-dependencies]").next().unwrap();
    let names: Vec<&str> = deps.lines().filter_map(|l| l.split('=').next()).map(str::trim).filter(|n| !n.is_empty()).collect();
    assert_eq!(names, ["sine-loco-strip", "jni", "zeroize"], "the isolated library must not link vault, net, store or chat code");
}
