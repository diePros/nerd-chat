package app.sineloco

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.sineloco.model.Palettes
import app.sineloco.ui.DarkMode
import app.sineloco.ui.SineApp

class MainActivity : ComponentActivity() {
    /** a pairing link that arrived as a `sineloco:` link (QR code, another app); in memory only, it pre-fills the pairing form and is dropped */
    private var incoming by mutableStateOf<app.sineloco.model.PairLink?>(null)
    private var pendingSave: String? = null
    private var pickCallback: ((String) -> Unit)? = null

    // the system pickers (no storage permission needed: the user chooses the file, we get that one file)
    private val savePicker = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val t = pendingSave; pendingSave = null
        if (uri != null && t != null) try { contentResolver.openOutputStream(uri)?.use { it.write(t.toByteArray()) } } catch (_: Exception) { }
    }
    private val openPicker = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.OpenDocument()) { uri ->
        val cb = pickCallback; pickCallback = null
        // read OFF the main thread (a slow provider must not freeze the app) and hand the text back on it
        if (uri != null && cb != null) Thread { val t = readSmallText(uri); runOnUiThread { if (t != null) cb(t) } }.start()
    }

    /** At most 8 KiB, read by hand: `InputStream.readNBytes(int)` only exists from Android 13 and this app runs on 10. Any failure (also an Error) means "no text", never a crash. */
    private fun readSmallText(uri: android.net.Uri): String? = try {
        contentResolver.openInputStream(uri)?.use { s ->
            val out = java.io.ByteArrayOutputStream(); val buf = ByteArray(1024); var total = 0
            while (true) { val n = s.read(buf); if (n < 0) break; total += n; if (total > 8 * 1024) return@use null; out.write(buf, 0, n) }
            String(out.toByteArray(), Charsets.UTF_8)
        }
    } catch (_: Throwable) { null }

    private fun handleIntent(i: android.content.Intent?) {
        val d = i?.data ?: return
        if (i.action == android.content.Intent.ACTION_VIEW && d.scheme == "sineloco") incoming = app.sineloco.model.PairLink.parse(d.toString())
        i.data = null // not kept in the activity's intent either
    }

    override fun onNewIntent(intent: android.content.Intent) { super.onNewIntent(intent); handleIntent(intent) }

    private val platform = object : app.sineloco.ui.PlatformActions {
        override fun copy(text: String) = copySensitive(text)
        override fun share(text: String) {
            val send = android.content.Intent(android.content.Intent.ACTION_SEND).setType("text/plain").putExtra(android.content.Intent.EXTRA_TEXT, text)
            try { startActivity(android.content.Intent.createChooser(send, null)) } catch (_: Exception) { }
        }
        // a NEUTRAL random file name: a suggested "sineloco-contact.txt" would advertise the app in Downloads and in any cloud drive the file lands in
        override fun saveText(suggestedName: String, text: String) {
            val rnd = java.security.SecureRandom(); val name = "note-" + (1..6).joinToString("") { "0123456789abcdef"[rnd.nextInt(16)].toString() } + ".txt"
            pendingSave = text; try { savePicker.launch(name) } catch (_: Exception) { pendingSave = null }
        }
        override fun pickText(onText: (String) -> Unit) { pickCallback = onText; try { openPicker.launch(arrayOf("text/*", "application/octet-stream")) } catch (_: Exception) { pickCallback = null } }
        /** Wi-Fi or Ethernet networks that are NOT a VPN: a "private" address on a VPN or on mobile data belongs to somebody else's network (the provider's, the carrier's). */
        private fun localLinks(): List<android.net.LinkAddress> {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            return cm.allNetworks.filter { n ->
                val c = cm.getNetworkCapabilities(n)
                c != null && !c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) &&
                    (c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) || c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET))
            }.flatMap { cm.getLinkProperties(it)?.linkAddresses.orEmpty() }.filter { (it.address as? java.net.Inet4Address)?.isSiteLocalAddress == true }
        }
        override fun lanAddresses(): List<String> = try { localLinks().mapNotNull { it.address.hostAddress }.distinct() } catch (_: Exception) { emptyList() }
        /** is `ip:port` inside the subnet of one of those links? (else the packets would leave through some other interface, a VPN for instance) */
        override fun onLink(addr: String): Boolean = try {
            val ip = java.net.InetAddress.getByName(addr.substringBeforeLast(':')).address
            localLinks().any { l ->
                val net = l.address.address; val bits = l.prefixLength
                ip.size == net.size && (0 until bits).all { i -> (ip[i / 8].toInt() shr (7 - i % 8) and 1) == (net[i / 8].toInt() shr (7 - i % 8) and 1) }
            }
        } catch (_: Exception) { false }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, and a blank thumbnail in the recent-apps list.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        // no autofill service may offer to save the vault password; accessibility services get no content of this window (Android 14+)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= 34) window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)

        // Android 13+: the foreground service's notification needs the user's permission; asked once. Without it the service still works (it shows in the system's task list).
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            val asked = getSharedPreferences("look", Context.MODE_PRIVATE)
            if (!asked.getBoolean("asked_notifications", false)) {
                asked.edit().putBoolean("asked_notifications", true).apply()
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }
        // Back from the first screen only sends the app away AND locks it (consistently on every Android version: from 12 on the system would otherwise just move the task to the back
        // without finishing it, and the screen would stay readable). Inner screens handle Back themselves (the Compose BackHandler runs first).
        onBackPressedDispatcher.addCallback(this, object : androidx.activity.OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { (application as SineLocoApp).backend.lock(); moveTaskToBack(true) }
        })
        handleIntent(intent)
        val prefs = getSharedPreferences("look", Context.MODE_PRIVATE) // only the colour choice: nothing sensitive
        val palette = Palettes.byId(prefs.getString("palette", null))
        val mode = runCatching { DarkMode.valueOf(prefs.getString("mode", null) ?: "") }.getOrDefault(DarkMode.System)
        val backend = (application as SineLocoApp).backend

        setContent {
            NoKeyboardLearning {
            SineApp(
                backend = backend, initialPalette = palette, initialMode = mode,
                onThemeChanged = { p, m -> prefs.edit().putString("palette", p.id).putString("mode", m.name).apply() },
                backHandler = { enabled, onBack -> BackHandler(enabled, onBack) },
                onCopy = ::copySensitive,
                platform = platform, incomingLink = incoming, onIncomingLinkUsed = { incoming = null },
                onExit = { finishAndRemoveTask(); android.os.Process.killProcess(android.os.Process.myPid()) },
            )
            }
        }
    }

    /** Coming back: ask the core for its state, which runs the lock's deadline check first (a timed-out lock has erased itself and the screen shows the first-unlock prompt). */
    override fun onStart() {
        super.onStart()
        (application as SineLocoApp).backend.refresh()
    }

    /** Leaving the screen (home, recents, another app) locks the app: it keeps running, but whoever opens it next needs the password. A rotation is not leaving. */
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) (application as SineLocoApp).backend.lock()
    }

    /**
     * Leaving the app for good (swipe-away from the recent apps, exit) ends the session in EVERY state: wipe, then die. (Back no longer finishes: it locks. Anything else that
     * finishes the activity, for instance another app starting it with CLEAR_TASK, also wipes: a denial of service at worst, never a leak.) Without this an unlocked
     * vault would stay in a cached process whenever the foreground service is not running (offline, failed start), and the launcher icon would open it without a password.
     * A rotation or other configuration change is not leaving.
     */
    override fun onDestroy() {
        val leaving = isFinishing && !isChangingConfigurations
        super.onDestroy()
        if (leaving) (application as SineLocoApp).wipeAndExit()
    }

    /** Clipboard copy marked sensitive (Android 13+ hides it from the paste preview and keyboard suggestions). */
    private fun copySensitive(text: String) {
        val clip = ClipData.newPlainText("", text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
    }
}

/**
 * Compose never sets IME_FLAG_NO_PERSONALIZED_LEARNING or TYPE_TEXT_FLAG_NO_SUGGESTIONS (turning auto-correct off only leaves one flag out), so a keyboard such as
 * Gboard would add typed contact names and messages to its personal dictionary: a lasting copy OUTSIDE the app that panic and purge cannot remove. This wraps every
 * text field of the app and adds both flags to what the keyboard is told. RUNTIME EFFECT NOT VERIFIED ON A DEVICE (it compiles; a keyboard may still ignore the flag).
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun NoKeyboardLearning(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = PlatformTextInputInterceptor { request, nextHandler ->
            nextHandler.startInputMethod(object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                    val connection = request.createInputConnection(outAttributes)
                    outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    if (outAttributes.inputType and InputType.TYPE_MASK_CLASS == InputType.TYPE_CLASS_TEXT) outAttributes.inputType = outAttributes.inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    return connection
                }
            })
        },
        content = content,
    )
}

