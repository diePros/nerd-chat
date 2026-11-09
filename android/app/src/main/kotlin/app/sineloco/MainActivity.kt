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
                onExit = { finishAndRemoveTask(); android.os.Process.killProcess(android.os.Process.myPid()) },
            )
            }
        }
    }

    /** Leaving the screen (home, recents, another app) locks the app: it keeps running, but whoever opens it next needs the password. A rotation is not leaving. */
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) (application as SineLocoApp).backend.lock()
    }

    /**
     * Leaving the app for good (back from the first screen, swipe-away from the recent apps, exit) ends the session in EVERY state: wipe, then die. Without this an unlocked
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

