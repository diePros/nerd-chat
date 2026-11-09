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
import androidx.compose.ui.graphics.asImageBitmap
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
    private companion object { const val PICKER_GRACE_MS = 120_000L }

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

    // ---- photos: the picked picture is only READ here (bytes, never decoded in this process); the isolated media process re-encodes it, then the core offers it
    private var photoBitmap: android.graphics.Bitmap? = null
    private var photoGen = 0
    /** the contact a picked photo is FOR: fixed when the picker opens, so that opening another chat meanwhile cannot redirect it */
    private var photoContact = -1
    /** the re-encoded copy of a received photo, waiting for the user's save location (made BEFORE the picker opens: the picker covers the app and the app may lock) */
    private var pendingSaveBytes: ByteArray? = null
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var lockAfterPicker: Runnable? = null
    private var pickerUntil = 0L

    /** A system picker covers this activity and stops it, which normally locks the app. For ONE picker request the lock waits (at most [PICKER_GRACE_MS]): a lock that wipes the pane before the answer arrives makes Send and Save impossible. The screen turning off still locks at once. */
    private fun pickerOpens() { pickerUntil = android.os.SystemClock.elapsedRealtime() + PICKER_GRACE_MS }

    private fun lockNow() {
        photoBitmap = null; photoGen++
        pendingSaveBytes?.fill(0); pendingSaveBytes = null
        (application as SineLocoApp).backend.lock()
    }

    private val photoPicker = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia()) { uri ->
        val contact = photoContact; photoContact = -1
        if (uri != null && contact >= 0) Thread { sendPhoto(contact, uri) }.start()
    }
    private val photoSaver = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.CreateDocument("image/jpeg")) { uri ->
        val bytes = pendingSaveBytes; pendingSaveBytes = null
        if (bytes == null) return@registerForActivityResult
        if (uri == null) { bytes.fill(0); return@registerForActivityResult }
        Thread {
            try { contentResolver.openOutputStream(uri)?.use { it.write(bytes) } } catch (_: Exception) { note("The photo could not be saved.") } finally { bytes.fill(0) }
        }.start()
    }

    private fun note(text: String) = runOnUiThread { android.widget.Toast.makeText(this, text, android.widget.Toast.LENGTH_LONG).show() }

    /** At most 32 MiB (a camera original), read by hand into a buffer that is wiped afterwards: any failure (also an Error) means "no photo", never a crash. */
    private fun readPhoto(uri: android.net.Uri): ByteArray? {
        val out = WipingBuffer(1 shl 20)
        return try {
            contentResolver.openInputStream(uri)?.use { s ->
                val buf = ByteArray(1 shl 16); var total = 0
                try { while (true) { val n = s.read(buf); if (n < 0) break; total += n; if (total > app.sineloco.clean.CleanerService.MAX_IN) return@use null; out.write(buf, 0, n) } } finally { buf.fill(0) }
                out.toByteArray()
            }
        } catch (_: Throwable) { null } finally { out.wipe() }
    }

    private fun sendPhoto(contact: Int, uri: android.net.Uri) {
        val app = application as SineLocoApp
        val media = app.media ?: return note("Photos are not available in this build.")
        val raw = readPhoto(uri) ?: return note("That picture could not be read (or is larger than 32 MB).")
        val jpeg = try { media.reencode(raw) } finally { raw.fill(0) }
        if (jpeg == null) return note("That picture could not be prepared. Only ordinary photos work.")
        app.backend.sendPhoto(contact, jpeg) // the backend wipes the array; the core refuses it when another chat is open by now
    }

    /** Fetch the received photo, make a CLEAN COPY of it in the isolated process (what the sender's bytes would do to the gallery's own parsers is not our business to find out), then ask where to save it. */
    private fun startSavePhoto() {
        val app = application as SineLocoApp
        val media = app.media ?: return
        Thread {
            val bytes = app.backend.receivedPhoto() ?: return@Thread note("The photo is no longer in memory.")
            val copy = try { media.reencode(bytes) } finally { bytes.fill(0) }
            if (copy == null) return@Thread note("The photo could not be prepared for saving.")
            runOnUiThread {
                pendingSaveBytes?.fill(0); pendingSaveBytes = copy
                val rnd = java.security.SecureRandom(); val name = "img-" + (1..6).joinToString("") { "0123456789abcdef"[rnd.nextInt(16)].toString() } + ".jpg"
                pickerOpens()
                try { photoSaver.launch(name) } catch (_: Exception) { pendingSaveBytes?.fill(0); pendingSaveBytes = null }
            }
        }.start()
    }

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
        override val photos: Boolean get() = (application as SineLocoApp).media != null
        override fun pickPhoto(contactId: Int) {
            photoContact = contactId; pickerOpens()
            try { photoPicker.launch(androidx.activity.result.PickVisualMediaRequest(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia.ImageOnly)) } catch (_: Exception) { photoContact = -1 }
        }
        override fun loadPhoto(onLoaded: (androidx.compose.ui.graphics.ImageBitmap?) -> Unit) {
            val app = application as SineLocoApp
            val gen = ++photoGen
            Thread {
                val bytes = app.backend.receivedPhoto()
                val bmp = try { bytes?.let { app.media?.decode(it) } } finally { bytes?.fill(0) }
                // a result that arrives after the viewer was closed, the chat left or the app locked is dropped
                runOnUiThread { if (gen == photoGen) { photoBitmap = bmp; onLoaded(bmp?.asImageBitmap()) } else bmp?.eraseColor(0) }
            }.start()
        }
        override fun savePhoto() = startSavePhoto()
        override fun forgetPhoto() { photoBitmap?.eraseColor(0); photoBitmap = null; photoGen++ }
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
        lockAfterPicker?.let { handler.removeCallbacks(it) }; lockAfterPicker = null; pickerUntil = 0
        (application as SineLocoApp).backend.refresh()
    }

    /** Leaving the screen (home, recents, another app) locks the app: it keeps running, but whoever opens it next needs the password. A rotation is not leaving. */
    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) return
        val left = pickerUntil - android.os.SystemClock.elapsedRealtime()
        if (left > 0) { val r = Runnable { lockNow() }; lockAfterPicker = r; handler.postDelayed(r, left) } else lockNow()
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

