//! The hostile-file cleaner of the phone: ONE call into a Kotlin object (`app.sineloco.model.MediaCleaner`), `clean(request: ByteArray): ByteArray?`, which runs
//! `sine-loco-android-clean` in an `isolatedProcess` service (no permissions, no network, no app storage). Request and answer are the `strip::wire` frames; the answer is
//! decoded here as untrusted input. Plain safe Rust (the `jni` crate's safe API).
//! If the cleaner is missing or fails, the file is REFUSED. There is no fallback to parsing in this process, which holds the keys.
use jni::{objects::{GlobalRef, JByteArray, JObject, JValue}, JNIEnv, JavaVM};
use sine_loco_strip::{wire, Cleaned, Mode, StripError, MAX_INPUT};
use std::sync::OnceLock;
use zeroize::Zeroizing;

static MEDIA: OnceLock<Option<JniMedia>> = OnceLock::new();

pub struct JniMedia { vm: JavaVM, obj: GlobalRef }

/// Install the Kotlin cleaner as the process-wide cleaner of the core (`strip::set_cleaner`). Called once; a null object installs a cleaner that refuses everything,
/// so a missing media process can never turn into in-process parsing of hostile files.
pub fn install(env: &JNIEnv, obj: &JObject) {
    let m = if obj.is_null() { None } else { env.get_java_vm().ok().zip(env.new_global_ref(obj).ok()).map(|(vm, obj)| JniMedia { vm, obj }) };
    let _ = MEDIA.set(m);
    sine_loco_strip::set_cleaner(android_clean);
}

fn android_clean(d: &[u8], mode: Mode) -> Result<Cleaned, StripError> {
    let refuse = |m: &str| StripError::Refused(m.into());
    if d.len() > MAX_INPUT { return Err(StripError::TooLarge); }
    let Some(Some(m)) = MEDIA.get() else { return Err(refuse("no isolated media process on this phone: the file was NOT opened")) };
    let req = Zeroizing::new(wire::encode_request(mode, d));
    let ans = m.call(&req).ok_or_else(|| refuse("the isolated media process failed or timed out: the file was NOT opened"))?;
    wire::decode_response(&ans)
}

impl JniMedia {
    fn call(&self, request: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let mut env = self.vm.attach_current_thread().ok()?;
        let arr = env.byte_array_from_slice(request).ok()?;
        let r = env.call_method(&self.obj, "clean", "([B)[B", &[JValue::Object(&arr)]);
        let _ = env.set_byte_array_region(&arr, 0, &vec![0i8; request.len()]);
        let obj = match r.and_then(|v| v.l()) { Ok(o) => o, Err(_) => { if env.exception_check().unwrap_or(false) { let _ = env.exception_clear(); } return None } };
        if obj.is_null() { return None; }
        let out = JByteArray::from(obj);
        // the answer is at most the cleaned file plus a small frame: refuse more before copying it
        let n = env.get_array_length(&out).ok()?;
        if n < 0 || n as usize > MAX_INPUT + 8192 { return None; }
        let bytes = Zeroizing::new(env.convert_byte_array(&out).ok()?);
        let _ = env.set_byte_array_region(&out, 0, &vec![0i8; bytes.len()]);
        Some(bytes)
    }
}
