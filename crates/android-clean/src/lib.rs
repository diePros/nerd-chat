//! The cleaner for hostile files, as a library that Android loads into an `isolatedProcess` service (no permissions, no network, no app storage, its own
//! seccomp policy from the system). Request and answer are the SAME `strip::wire` frames the Linux helper uses, so the core decodes the answer as untrusted input.
//! `nClean(request: ByteArray): ByteArray` is the only export. Nothing but `sine-loco-strip` is linked in: this library holds no key and cannot reach one.
// allowed only for the `#[no_mangle]` export (the compiler counts it as unsafe); no unsafe block exists (tests/hygiene.rs)
#![allow(unsafe_code)]
use jni::{objects::{JByteArray, JObject}, sys::jbyteArray, JNIEnv};
use sine_loco_strip::{wire, StripError, MAX_INPUT};
use zeroize::Zeroizing;

/// One request frame in, one answer frame out. Pure, so the host tests it without a JVM.
pub fn handle(request: &[u8]) -> Vec<u8> {
    match wire::decode_request(request) {
        Some((mode, data)) => wire::encode_response(&sine_loco_strip::clean(data, mode)),
        None => wire::encode_response(&Err(StripError::Refused("bad request".into()))),
    }
}

#[no_mangle]
pub extern "system" fn Java_app_sineloco_clean_CleanerNative_nClean<'l>(mut env: JNIEnv<'l>, _this: JObject<'l>, request: JByteArray<'l>) -> jbyteArray {
    let refuse = |env: &mut JNIEnv| env.byte_array_from_slice(&wire::encode_response(&Err(StripError::Refused("bad request".into())))).map(JByteArray::into_raw).unwrap_or(std::ptr::null_mut());
    if request.is_null() { return refuse(&mut env); }
    // oversized input is refused BEFORE it is copied
    if env.get_array_length(&request).map(|n| n < 0 || n as usize > MAX_INPUT + 16).unwrap_or(true) { return refuse(&mut env); }
    let req = match env.convert_byte_array(&request) { Ok(b) => Zeroizing::new(b), Err(_) => return refuse(&mut env) };
    let answer = Zeroizing::new(handle(&req));
    env.byte_array_from_slice(&answer).map(JByteArray::into_raw).unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sine_loco_strip::{Mode, Format};

    fn jpeg_with_exif() -> Vec<u8> {
        let seg = |m: u8, body: &[u8]| { let mut v = vec![0xFF, m]; v.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes()); v.extend_from_slice(body); v };
        let mut j = vec![0xFF, 0xD8];
        j.extend(seg(0xE1, b"Exif\0\0GPS-SECRET"));
        j.extend(seg(0xDB, &[0; 65])); j.extend(seg(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0])); j.extend(seg(0xC4, &[0; 17])); j.extend(seg(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        j.extend(vec![0x11u8; 100]); j.extend_from_slice(&[0xFF, 0xD9]);
        j
    }

    #[test]
    fn a_request_frame_is_cleaned_and_answered_in_the_same_wire_format() {
        let ans = handle(&wire::encode_request(Mode::Auto, &jpeg_with_exif()));
        let c = wire::decode_response(&ans).expect("a valid, cleaned answer");
        assert_eq!(c.format, Format::Jpeg);
        assert!(!c.data.windows(10).any(|w| w == b"GPS-SECRET"));
    }

    #[test]
    fn junk_and_unknown_formats_are_refused_not_passed_on() {
        assert!(wire::decode_response(&handle(b"not a frame")).is_err());
        assert!(wire::decode_response(&handle(&wire::encode_request(Mode::Auto, b"%PDF-1.7 hostile"))).is_err());
    }
}
