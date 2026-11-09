package app.sineloco.model

/** The JNI calls into `libsineloco_bridge.so` (`crates/android`). Kept behind an interface so [RustBackend] can be tested with a fake. */
interface Native {
    /** Open the vault directory; returns the first snapshot (a `"screen":"error"` snapshot if the directory is unusable). [keys]: the deletable key store for the history (null: its keys are stored inside the encrypted file and cannot be destroyed separately). [historyDefault]: what is kept until the user chooses (a [Persist] ordinal: 0 nothing, 1 unsent only, 2 a day, 3 a week). */
    fun init(vaultDir: String, lowMem: Boolean, torPath: String?, historyDefault: Int, keys: PlatformKeys?, media: MediaCleaner? = null): String

    /** One operation (see `crates/android/src/bridge.rs`); returns the new snapshot. [arg] is NOT wiped here, the caller does it. */
    fun call(op: String, arg: CharArray?): String

    /** Offer a photo (JPEG bytes the isolated media process already re-encoded) to the open chat's contact; returns the new snapshot. The caller wipes [data]. */
    fun sendFile(data: ByteArray): String = ""

    /** The re-cleaned file received in the open chat, or null. The caller wipes the array after use. */
    fun fileBytes(): ByteArray? = null
}

/**
 * The real thing. The symbol names are fixed by this class name and package (`Java_app_sineloco_model_NativeBridge_nInit`...): renaming this
 * object breaks the library, and the Rust hygiene test pins the names.
 */
object NativeBridge : Native {
    private var loaded = false

    /** Load the library: by name on Android (it is in the APK), or by absolute path on a development machine. */
    @Synchronized fun load(path: String? = null) {
        if (loaded) return
        if (path == null) System.loadLibrary("sineloco_bridge") else System.load(path)
        loaded = true
    }

    private external fun nInit(dir: String, lowMem: Boolean, torPath: String?, historyDefault: Int, keys: PlatformKeys?, media: MediaCleaner?): String
    private external fun nCall(op: String, arg: CharArray?): String
    private external fun nSendFile(data: ByteArray): String
    private external fun nFileBytes(): ByteArray?

    override fun init(vaultDir: String, lowMem: Boolean, torPath: String?, historyDefault: Int, keys: PlatformKeys?, media: MediaCleaner?): String = nInit(vaultDir, lowMem, torPath, historyDefault, keys, media)
    override fun call(op: String, arg: CharArray?): String = nCall(op, arg)
    override fun sendFile(data: ByteArray): String = nSendFile(data)
    override fun fileBytes(): ByteArray? = nFileBytes()
}
