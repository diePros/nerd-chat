//! The Android Keystore as the history's [`PlatformKeys`]: three calls into a Kotlin object (`app.nerdchat.model.PlatformKeys`):
//! `wrap(epoch: Int, key: ByteArray): ByteArray?`, `unwrap(epoch: Int, blob: ByteArray): ByteArray?`, `erase(epoch: Int)`.
//! Plain safe Rust (the `jni` crate's safe API). Key bytes cross as Java byte arrays that are overwritten with zeros right after the call (best effort:
//! the garbage collector may have copied them, like every secret on the JVM; the bucket keys are short-lived and each protects at most six hours of messages).
use jni::{
    objects::{GlobalRef, JByteArray, JValue},
    JNIEnv, JavaVM,
};
use nerd_chat_store::history::PlatformKeys;
use zeroize::Zeroizing;

pub struct JniKeys { vm: JavaVM, obj: GlobalRef }

impl JniKeys {
    pub fn new(env: &JNIEnv, obj: &jni::objects::JObject) -> Option<Self> {
        if obj.is_null() { return None; }
        Some(Self { vm: env.get_java_vm().ok()?, obj: env.new_global_ref(obj).ok()? })
    }

    fn call_bytes(&self, name: &str, epoch: u32, input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let mut env = self.vm.attach_current_thread().ok()?;
        let arr = env.byte_array_from_slice(input).ok()?;
        let r = env.call_method(&self.obj, name, "(I[B)[B", &[JValue::Int(epoch as i32), JValue::Object(&arr)]);
        let _ = env.set_byte_array_region(&arr, 0, &vec![0i8; input.len()]);
        let obj = match r { Ok(v) => v.l().ok(), Err(_) => { if env.exception_check().unwrap_or(false) { let _ = env.exception_clear(); } None } }?;
        if obj.is_null() { return None; }
        let out = JByteArray::from(obj);
        let bytes = Zeroizing::new(env.convert_byte_array(&out).ok()?);
        let n = bytes.len();
        let _ = env.set_byte_array_region(&out, 0, &vec![0i8; n]);
        Some(bytes)
    }
}

impl PlatformKeys for JniKeys {
    fn wrap(&self, epoch: u32, key: &[u8; 32]) -> Option<Vec<u8>> { self.call_bytes("wrap", epoch, key).map(|z| z.to_vec()) }
    fn unwrap(&self, epoch: u32, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        let b = self.call_bytes("unwrap", epoch, blob)?;
        let a: [u8; 32] = b.as_slice().try_into().ok()?;
        Some(Zeroizing::new(a))
    }
    fn erase(&self, epoch: u32) {
        let Ok(mut env) = self.vm.attach_current_thread() else { return };
        if env.call_method(&self.obj, "erase", "(I)V", &[JValue::Int(epoch as i32)]).is_err() && env.exception_check().unwrap_or(false) { let _ = env.exception_clear(); }
    }
}
