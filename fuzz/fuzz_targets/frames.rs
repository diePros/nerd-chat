//! Application frames an authenticated but hostile contact can send inside the encrypted session: text chunks, file offer/chunk/control
//! frames, padded file streams, key-rotation frames.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nerd_chat_chat::{file, proto};

fuzz_target!(|d: &[u8]| {
    let mut a = proto::Assembler::new();
    let _ = a.feed(d);
    let _ = a.feed(&[proto::KIND_TEXT_FINAL]); // reassembly state must stay consistent after any input
    let _ = file::parse_offer(d);
    let _ = file::parse_ctl(d);
    let _ = file::parse_chunk(d);
    let _ = file::parse_stream(d);
    let _ = proto::parse_rotate(d);
    let _ = file::valid_bucket(d.len());
});
