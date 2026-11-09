package app.nerdchat

import android.app.ActivityManager
import android.app.Application
import android.content.Context
import app.nerdchat.model.ChatBackend
import app.nerdchat.model.FakeBackend
import app.nerdchat.model.NativeBridge
import app.nerdchat.model.RustBackend
import java.io.File

/**
 * Owns the backend so it survives the activity being recreated. The real one is the Rust core over JNI ([RustBackend]); a build with `-Pdemo`
 * uses the in-memory demo backend instead (any 12+ character password, nothing stored, nothing sent).
 */
class NerdChatApp : Application() {
    lateinit var backend: ChatBackend
        private set

    override fun onCreate() {
        super.onCreate()
        backend = if (resources.getBoolean(R.bool.nerdchat_demo)) FakeBackend(hasVault = false) else rust()
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
        // Encrypted outbox ON by default on the phone: the OS kills the app at will, and the contact is rarely online at the same moment. The user can switch it off in Settings.
        return RustBackend(NativeBridge, dir.path, lowMem, tor, keepOutboxDefault = true)
    }
}
