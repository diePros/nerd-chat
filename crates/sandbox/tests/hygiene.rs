//! "Exactly one unsafe block" is a project promise, but `#![deny(unsafe_code)]` + `#[allow]` cannot enforce it (`forbid` cannot be
//! overridden, so it cannot be used here). This test does, on the TOKENS of every source file of the crate (comments and string
//! literals removed, so spacing/newline/comment tricks do not matter) and on the crate layout (no build script, no extra modules,
//! no `#[path]`/`include!`, a single source file).
use std::{fs, path::{Path, PathBuf}};

/// Remove `//` and (nested) `/* */` comments and the contents of "..." / r#"..."# / '.' literals, keeping the rest verbatim.
fn strip(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let (mut i, mut out) = (0, String::new());
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') { while i < b.len() && b[i] != '\n' { i += 1; } continue; }
        if c == '/' && next == Some('*') {
            let mut depth = 1; i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') { depth += 1; i += 2; }
                else if b[i] == '*' && b.get(i + 1) == Some(&'/') { depth -= 1; i += 2; }
                else { i += 1; }
            }
            out.push(' ');
            continue;
        }
        // raw strings r"..." r#"..."#
        if c == 'r' && matches!(next, Some('"') | Some('#')) && (i == 0 || !(b[i - 1].is_alphanumeric() || b[i - 1] == '_')) {
            let mut j = i + 1; let mut hashes = 0;
            while b.get(j) == Some(&'#') { hashes += 1; j += 1; }
            if b.get(j) == Some(&'"') {
                j += 1;
                loop {
                    if j >= b.len() { break; }
                    if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) { j += 1 + hashes; break; }
                    j += 1;
                }
                out.push_str("\"\"");
                i = j;
                continue;
            }
        }
        if c == '"' {
            i += 1;
            while i < b.len() && b[i] != '"' { if b[i] == '\\' { i += 1; } i += 1; }
            i += 1;
            out.push_str("\"\"");
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn words(s: &str) -> Vec<String> {
    let mut v = Vec::new(); let mut cur = String::new();
    for c in s.chars() { if c.is_alphanumeric() || c == '_' { cur.push(c); } else if !cur.is_empty() { v.push(std::mem::take(&mut cur)); } }
    if !cur.is_empty() { v.push(cur); }
    v
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() { rs_files(&p, out); } else if p.extension().is_some_and(|x| x == "rs") { out.push(p); }
    }
}

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")) }

#[test]
fn the_crate_has_one_source_file_and_no_build_script() {
    let mut files = Vec::new();
    rs_files(&root().join("src"), &mut files);
    assert_eq!(files.len(), 1, "src must contain exactly lib.rs: {files:?}");
    assert!(!root().join("build.rs").exists(), "no build script (it could contain unsafe code or generate it)");
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("build =") && !manifest.contains("proc-macro"), "no build script / proc-macro in the manifest");
}

#[test]
fn exactly_one_unsafe_keyword_and_the_lint_attributes_are_what_we_expect() {
    let src = fs::read_to_string(root().join("src/lib.rs")).unwrap();
    let code = strip(&src);
    let w = words(&code);
    let count = |x: &str| w.iter().filter(|t| t.as_str() == x).count();
    assert_eq!(count("unsafe"), 1, "the crate must contain exactly ONE `unsafe` token (the prctl call)");
    // `unsafe_code` appears in exactly: #![deny(unsafe_code)] and #[allow(unsafe_code)]
    assert_eq!(count("unsafe_code"), 2);
    assert_eq!(code.matches("deny(unsafe_code)").count() + code.matches("deny ( unsafe_code )").count(), 1);
    for t in ["asm", "global_asm", "extern", "transmute", "transmute_copy", "from_raw", "from_raw_parts", "get_unchecked", "static_mut", "include", "include_str", "include_bytes", "path", "macro_rules", "link", "no_mangle", "link_section", "ctor"] {
        assert_eq!(count(t), 0, "`{t}` must not appear in the sandbox crate");
    }
    assert_eq!(count("mod"), 0, "no modules (a second file would escape this check)");
    assert_eq!(count("static"), 0);
    assert!(!code.contains("#[path"), "#[path] is not allowed");
}

#[test]
fn the_unsafe_block_is_documented_and_calls_only_prctl() {
    let src = fs::read_to_string(root().join("src/lib.rs")).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let at = lines.iter().position(|l| l.contains("unsafe {")).expect("the unsafe block");
    assert!(lines[at].contains("libc::prctl("), "the unsafe block must be the prctl call");
    assert_eq!(lines[at].matches("libc::").count() - lines[at].matches("libc::c_ulong").count() - lines[at].matches("libc::sock_fprog").count(), 3, "prctl + its two constants only: {}", lines[at]);
    assert!(lines[at - 1].trim_start().starts_with("// SAFETY:") || lines[at - 2].trim_start().starts_with("// SAFETY:"), "missing SAFETY comment");
}

#[test]
fn the_stripper_itself_works() {
    let s = strip("let a = \"unsafe {\"; // unsafe\n/* unsafe /* nested */ unsafe */ let r = r#\"unsafe\"#; unsafe{}");
    let w = words(&s);
    assert_eq!(w.iter().filter(|t| t.as_str() == "unsafe").count(), 1, "{s}");
    assert_eq!(words("unsafe\n{ r#unsafe unsafe /*x*/ {").iter().filter(|t| t.as_str() == "unsafe").count(), 3);
}
