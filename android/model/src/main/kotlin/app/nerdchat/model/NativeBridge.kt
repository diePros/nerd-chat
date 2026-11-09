package app.nerdchat.model

/** The two JNI calls into `libnerdchat_bridge.so` (`crates/android`). Kept behind an interface so [RustBackend] can be tested with a fake. */
interface Native {
    /** Open the vault directory; returns the first snapshot (a `"screen":"error"` snapshot if the directory is unusable). */
    fun init(vaultDir: String, lowMem: Boolean, torPath: String?): String

    /** One operation (see `crates/android/src/bridge.rs`); returns the new snapshot. [arg] is NOT wiped here, the caller does it. */
    fun call(op: String, arg: CharArray?): String
}

/**
 * The real thing. The symbol names are fixed by this class name and package (`Java_app_nerdchat_model_NativeBridge_nInit`...): renaming this
 * object breaks the library, and the Rust hygiene test pins the names.
 */
object NativeBridge : Native {
    private var loaded = false

    /** Load the library: by name on Android (it is in the APK), or by absolute path on a development machine. */
    @Synchronized fun load(path: String? = null) {
        if (loaded) return
        if (path == null) System.loadLibrary("nerdchat_bridge") else System.load(path)
        loaded = true
    }

    private external fun nInit(dir: String, lowMem: Boolean, torPath: String?): String
    private external fun nCall(op: String, arg: CharArray?): String

    override fun init(vaultDir: String, lowMem: Boolean, torPath: String?): String = nInit(vaultDir, lowMem, torPath)
    override fun call(op: String, arg: CharArray?): String = nCall(op, arg)
}
