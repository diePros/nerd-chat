package app.nerdchat

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.nerdchat.model.Palettes
import app.nerdchat.ui.DarkMode
import app.nerdchat.ui.NerdApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, and a blank thumbnail in the recent-apps list.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()

        val prefs = getSharedPreferences("look", Context.MODE_PRIVATE) // only the colour choice: nothing sensitive
        val palette = Palettes.byId(prefs.getString("palette", null))
        val mode = runCatching { DarkMode.valueOf(prefs.getString("mode", null) ?: "") }.getOrDefault(DarkMode.System)
        val backend = (application as NerdChatApp).backend

        setContent {
            NerdApp(
                backend = backend, initialPalette = palette, initialMode = mode,
                onThemeChanged = { p, m -> prefs.edit().putString("palette", p.id).putString("mode", m.name).apply() },
                backHandler = { enabled, onBack -> BackHandler(enabled, onBack) },
                onCopy = ::copySensitive,
                onExit = { finishAndRemoveTask(); android.os.Process.killProcess(android.os.Process.myPid()) },
            )
        }
    }

    /** Clipboard copy marked sensitive (Android 13+ hides it from the paste preview and keyboard suggestions). */
    private fun copySensitive(text: String) {
        val clip = ClipData.newPlainText("", text)
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
    }
}
