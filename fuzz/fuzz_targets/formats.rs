//! Parsers of data that reaches us from outside or from disk: a contact bundle (binary and armored text) and the vault's contact book.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|d: &[u8]| {
    let _ = sine_loco_core::bundle::Bundle::decode(d);
    let _ = sine_loco_store::Store::decode(d);
    if let Ok(t) = std::str::from_utf8(d) { let _ = sine_loco_exchange::file::dearmor(t); }
});
