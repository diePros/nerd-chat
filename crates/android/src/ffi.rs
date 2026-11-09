//! JNI entry points for `app.nerdchat.model.NativeBridge`. The ONLY module with `unsafe_code` allowed: the exported symbols need
//! `#[no_mangle]`, which the compiler counts as unsafe. There is no `unsafe` block anywhere in this crate (the `jni` crate's safe API is used);
//! `tests/hygiene.rs` keeps it that way.
#![allow(unsafe_code)]

use crate::bridge::{Bridge, Options};
use jni::{
    objects::{JCharArray, JObject, JString},
    sys::{jboolean, jstring, JNI_TRUE},
    JNIEnv,
};
use std::{path::PathBuf, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};

/// One bridge per process (one app, one vault). All calls come from one Kotlin thread; the mutex makes a second caller wait instead of race.
static BRIDGE: Mutex<Option<Bridge>> = Mutex::new(None);

fn out(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(JString::into_raw).unwrap_or(std::ptr::null_mut())
}

fn err_json(msg: &str) -> String {
    let mut w = crate::json::W::new();
    w.obj(); w.f_num("v", crate::snapshot::VERSION); w.f_str("screen", "error"); w.f_str("status", msg); w.f_bool("error", true); w.end_obj();
    w.finish().to_string()
}

/// `nInit(dir: String, lowMem: Boolean, torPath: String?, keepOutboxDefault: Boolean): String` -> a snapshot, or an `"error"` screen if the vault directory is unusable.
#[no_mangle]
pub extern "system" fn Java_app_nerdchat_model_NativeBridge_nInit<'l>(mut env: JNIEnv<'l>, _this: JObject<'l>, dir: JString<'l>, low_mem: jboolean, tor: JString<'l>, keep_outbox: jboolean) -> jstring {
    let dir: String = match env.get_string(&dir) { Ok(s) => s.into(), Err(_) => return out(&mut env, &err_json("bad directory argument")) };
    let tor_path = if tor.is_null() { None } else { env.get_string(&tor).ok().map(|s| PathBuf::from(String::from(s))) };
    let mut g = BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
    let json = match Bridge::new(std::path::Path::new(&dir), Options { low_mem: low_mem == JNI_TRUE, tor_path, keep_outbox_default: keep_outbox == JNI_TRUE }) {
        Ok(b) => { let s = b.snapshot(None); *g = Some(b); s.to_string() }
        Err(e) => err_json(&e),
    };
    drop(g);
    let r = out(&mut env, &json);
    json.into_bytes().zeroize();
    r
}

/// `nCall(op: String, arg: CharArray?): String` -> the new snapshot. The char array is copied into zeroizing memory and the copy wiped;
/// the CALLER wipes its own array.
#[no_mangle]
pub extern "system" fn Java_app_nerdchat_model_NativeBridge_nCall<'l>(mut env: JNIEnv<'l>, _this: JObject<'l>, op: JString<'l>, arg: JCharArray<'l>) -> jstring {
    let op: String = match env.get_string(&op) { Ok(s) => s.into(), Err(_) => return out(&mut env, &err_json("bad operation")) };
    let text: Zeroizing<String> = if arg.is_null() { Zeroizing::new(String::new()) } else {
        let len = env.get_array_length(&arg).unwrap_or(0).max(0) as usize;
        let mut units = Zeroizing::new(vec![0u16; len]);
        if env.get_char_array_region(&arg, 0, &mut units).is_err() { return out(&mut env, &err_json("bad argument")); }
        Zeroizing::new(char::decode_utf16(units.iter().copied()).map(|r| r.unwrap_or('\u{fffd}')).collect())
    };
    let mut g = BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
    let json = match g.as_mut() { Some(b) => b.call(&op, &text), None => Zeroizing::new(err_json("the bridge is not initialised")) };
    drop(g);
    let r = out(&mut env, &json);
    r
}
