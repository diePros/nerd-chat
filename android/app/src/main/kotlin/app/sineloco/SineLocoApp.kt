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
import app.sineloco.model.TorState

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
        if (backend !is FakeBackend) watchNetwork()
        lockWhenScreenGoesOff()
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
     * Tells the core when the phone's default network goes away or comes back (Wi-Fi <-> mobile data, airplane mode, no signal). "Up" means the network has the INTERNET capability;
     * it is deliberately NOT required to be "validated": a network that fails Android's own connectivity check (a captive portal, a censored network that still lets Tor through) must
     * not keep Tor from trying. No socket of ours is opened here: this is only the system's notification. The core pauses tor while the network is down and resumes it after a random delay.
     */
    private fun watchNetwork() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        // The state of THE default network, kept here so that "up" is computed from all of it (there is a network, it has INTERNET, our uid is not BLOCKED from it by a lockdown VPN,
        // Data Saver or a background restriction) and only CHANGES are sent to the core. Callbacks arrive on a system thread: everything is synchronized.
        val lock = Any()
        var current: android.net.Network? = null
        var caps: android.net.NetworkCapabilities? = null
        var blocked = false
        var last: Boolean? = null
        fun publish() {
            val up = current != null && caps?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) == true && !blocked
            if (up != last) { last = up; backend.networkChanged(up) }
        }
        val callback = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) { synchronized(lock) { if (current != network) { current = network; caps = null; blocked = false }; publish() } }
            override fun onCapabilitiesChanged(network: android.net.Network, c: android.net.NetworkCapabilities) { synchronized(lock) { current = network; caps = c; publish() } }
            override fun onBlockedStatusChanged(network: android.net.Network, b: Boolean) { synchronized(lock) { if (network == current) { blocked = b; publish() } } }
            // only the LOST default network counts: a hand-over may report the old one after the new one is already current
            override fun onLost(network: android.net.Network) { synchronized(lock) { if (network == current) { current = null; caps = null; blocked = false; publish() } } }
        }
        try { cm.registerDefaultNetworkCallback(callback) } catch (_: Exception) { return }
        // registration reports the current default network when there is one; when there is NONE it reports nothing, so say so (unless a callback was quicker)
        synchronized(lock) { if (current == null && last == null) { last = false; backend.networkChanged(false) } }
    }

    /**
     * Screen off (power button, timeout) locks the app, whatever is in front: the next look at the phone meets the password prompt. Screen ON runs the same call: if the lock's
     * time is up (the phone may have slept for hours), the core erases itself before anything is drawn (every call starts with the deadline check).
     */
    private fun lockWhenScreenGoesOff() {
        registerReceiver(object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: android.content.Intent?) { backend.lock() }
        }, android.content.IntentFilter().apply { addAction(android.content.Intent.ACTION_SCREEN_OFF); addAction(android.content.Intent.ACTION_SCREEN_ON) })
    }

    /**
     * The end of the session, in EVERY state (swipe-away, leaving the app, exit): the core wipes first (tor is killed and its directory removed synchronously, the vault and every secret
     * buffer are zeroized), then the process dies. A bare process kill would skip the zeroizing; the wait is bounded, so a busy core cannot keep the app alive.
     */
    fun wipeAndExit() {
        try { backend.panicBlocking(700) } catch (_: Exception) { }
        ConnectionService.stop(this)
        android.os.Process.killProcess(android.os.Process.myPid())
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
                        // Failed counts: the bridge restarts tor by itself, and a service that stopped on a failure could not be started again from the background (Android 12+)
                        // while tor is being shut down (`stopping`) the service stays: a frozen half-shutdown would leave the onion services published
                        val want = st.stopping || (!st.userOffline && (st.online || st.tor is TorState.Failed) && (st.stage == Stage.Ready || st.locked || (st.stage == Stage.Working && running)))
                        // the core erased itself (timed-out lock, too many wrong passwords, panic) with no screen to react: end the process
                        if (st.stage == Stage.Wiped) main.post { wipeAndExit() }
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
