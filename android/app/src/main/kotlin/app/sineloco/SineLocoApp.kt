package app.sineloco

import android.app.ActivityManager
import android.app.Application
import android.content.Context
import app.sineloco.model.ChatBackend
import app.sineloco.model.FakeBackend
import app.sineloco.model.NativeBridge
import app.sineloco.model.Persist
import app.sineloco.model.RustBackend
import android.os.Handler
import android.os.Looper
import java.io.File
import kotlin.concurrent.thread
import app.sineloco.model.Stage

/**
 * Owns the backend so it survives the activity being recreated. The real one is the Rust core over JNI ([RustBackend]); a build with `-Pdemo`
 * uses the in-memory demo backend instead (any 12+ character password, nothing stored, nothing sent).
 */
class SineLocoApp : Application() {
    lateinit var backend: ChatBackend
        private set

    override fun onCreate() {
        super.onCreate()
        backend = if (resources.getBoolean(R.bool.sineloco_demo)) FakeBackend(hasVault = false) else rust()
        watchConnection()
    }

    private fun rust(): ChatBackend {
        NativeBridge.load()
        // the vault directory: private to the app (0700 is enforced and checked by the core); excluded from every backup (see the manifest rules)
        val dir = File(filesDir, "vault")
        // Strong key derivation needs 512 MiB; below about 6 GiB of RAM use the 128 MiB profile (the core still opens either)
        val mem = ActivityManager.MemoryInfo().also { (getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).getMemoryInfo(it) }
        val lowMem = mem.totalMem < 6L * 1024 * 1024 * 1024
        // Tor ships as libtor.so in the native library directory (the only place Android 10+ allows executing from); not bundled yet
        val tor = File(applicationInfo.nativeLibraryDir, "libtor.so").takeIf { it.canExecute() }?.path
        // Messages are kept for a day by default on the phone: the OS kills the app at will and the contact is rarely online at the same moment. The user chooses in Settings.
        // expired history keys: destroyed now, and by a job every ~6 hours (also while the phone is locked)
        val keys = AndroidKeystoreKeys(getSharedPreferences("history", Context.MODE_PRIVATE))
        keys.eraseOlderThan(System.currentTimeMillis() / 1000)
        keys.ensureKeys(System.currentTimeMillis() / 1000)
        EraseJobService.schedule(this)
        return RustBackend(NativeBridge, dir.path, lowMem, tor, historyDefault = Persist.Day, keys = keys)
    }

    /**
     * The foreground service runs exactly while the user wants to be reachable AND the vault is unlocked: online, stage Ready. Offline, panic, purge or a locked vault stop it.
     * Only a change is acted on, and only from the main thread.
     */
    private fun watchConnection() {
        val main = Handler(Looper.getMainLooper())
        var running = false
        thread(isDaemon = true, name = "sineloco-connection-watch") {
            try {
                kotlinx.coroutines.runBlocking {
                    backend.state.collect { st ->
                        val want = st.online && st.stage == Stage.Ready
                        if (want != running) {
                            running = want
                            main.post { if (want) ConnectionService.start(this@SineLocoApp) else ConnectionService.stop(this@SineLocoApp) }
                        }
                    }
                }
            } catch (_: Exception) { }
        }
    }
}
