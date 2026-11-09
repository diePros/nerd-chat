#![deny(unsafe_code)]
//! Bridge between the Kotlin Android app and the Rust core (`nerd-chat-app`).
//!
//! Three layers, from the inside out:
//!  * [`bridge::Bridge`]: owns the `App` and a small COMMAND layer (what a tap means) over the core's key-driven state machine, the way
//!    the Linux GUI does it (`crates/gui/src/view.rs`, `Cmd`). It is plain safe Rust and is tested on the host without any JVM.
//!  * [`snapshot`]: the whole visible state as one JSON string (no serde: a ~100-line writer with its own tests), versioned with `"v"`.
//!  * [`ffi`]: the JNI entry points, `nInit` and `nCall`. It is the ONLY module that may contain `unsafe` (the exported symbols need
//!    `#[no_mangle]`, which the compiler counts as unsafe); `tests/hygiene.rs` pins that.
//!
//! Secrets cross the boundary as `char[]` that the Kotlin side wipes; here they go straight into the core's zeroizing buffers.
//! Messages leave the core inside the snapshot string: the Rust `String` is pre-sized and zeroized when dropped, BUT the `jni` crate makes its own
//! (unwiped) copy when it builds the Java string, and the Java `String` cannot be wiped at all (known gap G1, docs/ANDROID_PORT.md; tracker BR-3).
pub mod bridge;
pub mod json;
pub mod snapshot;
mod ffi;
