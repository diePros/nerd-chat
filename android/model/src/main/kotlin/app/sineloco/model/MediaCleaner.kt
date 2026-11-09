package app.sineloco.model

/**
 * The hostile-file cleaner, called from the core through JNI BY NAME (Rust: `crates/android/src/media.rs`; one method, `clean([B)[B`). The implementation runs the request in an
 * ISOLATED process (no permissions, no network, no app storage). [request] and the answer are `strip::wire` frames; the core decodes the answer as untrusted input.
 * Return null for ANY failure (timeout, process died): the core then refuses the file. It must never fall back to parsing in the calling process.
 * Do not rename this interface or its method.
 */
interface MediaCleaner {
    fun clean(request: ByteArray): ByteArray?
}
