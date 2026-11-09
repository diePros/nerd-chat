package app.sineloco.clean

/**
 * The one JNI call of `libsineloco_clean.so` (`crates/android-clean`). It is loaded ONLY in the isolated process ([CleanerService]); the main process, which holds the keys,
 * never loads it. The symbol name is fixed by this package and class name.
 */
object CleanerNative {
    fun load() = System.loadLibrary("sineloco_clean")
    /** a `strip::wire` request in, the answer frame out (a refusal is an answer, not an exception) */
    external fun nClean(request: ByteArray): ByteArray
}
