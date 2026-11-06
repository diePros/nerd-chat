//! Hostile file bytes into the metadata stripper (JPEG/PNG/text) and into the decoder of the sandboxed helper's answer.
//! Invariants: never panic (the release profile aborts the process), and cleaning is idempotent: whatever we output must clean to itself.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nerd_chat_strip::{clean, wire, Mode};

fuzz_target!(|d: &[u8]| {
    for mode in [Mode::Auto, Mode::PlainText] {
        if let Ok(c) = clean(d, mode) {
            let again = clean(&c.data, mode).expect("the cleaned output must itself be accepted");
            assert_eq!(again.data, c.data, "cleaning must be idempotent");
        }
    }
    let _ = wire::decode_response(d);
    let _ = wire::decode_request(d);
});
