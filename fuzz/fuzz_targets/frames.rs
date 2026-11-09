//! Application frames an authenticated but hostile contact can send inside the encrypted session: text chunks (with and without id),
//! delivery confirmations, capability frames, file offer/chunk/control frames, padded file streams, key-rotation frames, and SEQUENCES of
//! frames (the reassembly state machine must survive any order).
#![no_main]
use libfuzzer_sys::fuzz_target;
use nerd_chat_chat::{file, proto};

fuzz_target!(|d: &[u8]| {
    let mut a = proto::Assembler::new();
    let _ = a.feed(d);
    let _ = a.feed(&[proto::KIND_TEXT_FINAL]); // reassembly state must stay consistent after any input
    // Sequence mode: the input is cut into frames, [len byte][frame]..., all fed to ONE assembler.
    let mut seq = proto::Assembler::new();
    let mut rest = d;
    while let Some((&n, tail)) = rest.split_first() {
        let n = (n as usize).min(tail.len());
        let (f, r) = tail.split_at(n);
        if let Ok(proto::Incoming::Text(t, _)) = seq.feed(f) { assert!(t.len() <= proto::MAX_TEXT_BYTES); }
        let _ = proto::parse_caps(f);
        if let Some(ids) = proto::parse_msg_acks(f) { assert!(ids.len() <= proto::MAX_ACKS); }
        rest = r;
    }
    let _ = proto::parse_caps(d);
    let _ = proto::parse_msg_acks(d);
    let _ = file::parse_offer(d);
    let _ = file::parse_ctl(d);
    let _ = file::parse_chunk(d);
    let _ = file::parse_stream(d);
    let _ = proto::parse_rotate(d);
    let _ = file::valid_bucket(d.len());
});
