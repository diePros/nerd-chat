//! The Android Keystore as the history's [`PlatformKeys`]: three calls into a Kotlin object (`app.sineloco.model.PlatformKeys`):
//! `wrap(epoch: Int, key: ByteArray): ByteArray?`, `unwrap(epoch: Int, blob: ByteArray): ByteArray?`, `erase(epoch: Int)`.
//! Plain safe Rust (the `jni` crate's safe API). Key bytes cross as Java byte arrays that are overwritten with zeros right after the call (best effort:
//! the garbage collector may have copied them, like every secret on the JVM; the bucket keys are short-lived and each protects at most six hours of messages).
use jni::{
    objects::{GlobalRef, JByteArray, JValue},
    JNIEnv, JavaVM,
};
use sine_loco_store::history::{PlatformKeys, Unwrapped};
use zeroize::Zeroizing;

/// Result of a call into Kotlin: bytes, `null` ("no such key") or a failure (exception, binder error, empty array = Kotlin caught an error).
enum Call { Bytes(Zeroizing<Vec<u8>>), Null, Failed }

pub struct JniKeys { vm: JavaVM, obj: GlobalRef }

impl JniKeys {
    pub fn new(env: &JNIEnv, obj: &jni::objects::JObject) -> Option<Self> {
        if obj.is_null() { return None; }
        Some(Self { vm: env.get_java_vm().ok()?, obj: env.new_global_ref(obj).ok()? })
    }

    fn call_bytes(&self, name: &str, epoch: u32, input: &[u8]) -> Call {
        let Ok(mut env) = self.vm.attach_current_thread() else { return Call::Failed };
        let Ok(arr) = env.byte_array_from_slice(input) else { return Call::Failed };
        let r = env.call_method(&self.obj, name, "(I[B)[B", &[JValue::Int(epoch as i32), JValue::Object(&arr)]);
        let _ = env.set_byte_array_region(&arr, 0, &vec![0i8; input.len()]);
        let obj = match r.and_then(|v| v.l()) { Ok(o) => o, Err(_) => { if env.exception_check().unwrap_or(false) { let _ = env.exception_clear(); } return Call::Failed } };
        if obj.is_null() { return Call::Null; }
        let out = JByteArray::from(obj);
        let Ok(bytes) = env.convert_byte_array(&out) else { return Call::Failed };
        let bytes = Zeroizing::new(bytes);
        let n = bytes.len();
        let _ = env.set_byte_array_region(&out, 0, &vec![0i8; n]);
        if n == 0 { return Call::Failed; }
        Call::Bytes(bytes)
    }
}

impl PlatformKeys for JniKeys {
    fn wrap(&self, epoch: u32, key: &[u8; 32]) -> Option<Vec<u8>> { match self.call_bytes("wrap", epoch, key) { Call::Bytes(z) => Some(z.to_vec()), _ => None } }
    fn unwrap(&self, epoch: u32, blob: &[u8]) -> Unwrapped {
        match self.call_bytes("unwrap", epoch, blob) {
            Call::Bytes(b) => match <[u8; 32]>::try_from(b.as_slice()) { Ok(a) => Unwrapped::Key(Zeroizing::new(a)), Err(_) => Unwrapped::Failed },
            Call::Null => Unwrapped::Gone,
            Call::Failed => Unwrapped::Failed,
        }
    }
    fn erase(&self, epoch: u32) {
        let Ok(mut env) = self.vm.attach_current_thread() else { return };
        if env.call_method(&self.obj, "erase", "(I)V", &[JValue::Int(epoch as i32)]).is_err() && env.exception_check().unwrap_or(false) { let _ = env.exception_clear(); }
    }
}
