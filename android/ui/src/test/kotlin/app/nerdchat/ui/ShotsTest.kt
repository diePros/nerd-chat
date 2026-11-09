@file:OptIn(androidx.compose.ui.InternalComposeUiApi::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package app.nerdchat.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import app.nerdchat.model.*
import org.jetbrains.skia.EncodedImageFormat
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Renders the real screens headlessly (Skia) to PNG files in build/shots, one set per palette: the design review without a device. */
class ShotsTest {
    private val dir = File(System.getProperty("shots.dir") ?: "build/shots").also { it.mkdirs() }
    private val demo = FakeBackend.demoState()
    private fun contact(id: Int) = demo.chats.first { it.contact.id == id }.contact

    private fun render(name: String, content: @Composable () -> Unit): String {
        val scene = ImageComposeScene(width = 1080, height = 2200, density = Density(2.75f), content = content)
        var img = scene.render(0)
        for (t in 1..4) img = scene.render(t * 50_000_000L)
        val bytes = img.encodeToData(EncodedImageFormat.PNG)!!.bytes
        scene.close()
        File(dir, "$name.png").writeBytes(bytes)
        assertTrue(bytes.size > 5_000, "$name rendered something")
        return MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun screens(p: Palette, dark: Boolean, tag: String): Map<String, String> {
        val mode = if (dark) DarkMode.Dark else DarkMode.Light
        val m = mutableMapOf<String, String>()
        m["list"] = render("$tag-list") { NerdTheme(p, mode) { ChatListScreen(demo.chats, TorState.Ready, true, {}, {}, {}) } }
        m["chat"] = render("$tag-chat") { NerdTheme(p, mode) { ChatScreen(contact(1), demo.messages[1]!!, TorState.Ready, true, {}, {}, {}) } }
        m["unverified"] = render("$tag-chat-unverified") { NerdTheme(p, mode) { ChatScreen(contact(3), demo.messages[3]!!, TorState.Ready, true, {}, {}, {}) } }
        m["settings"] = render("$tag-settings") { NerdTheme(p, mode) { SettingsScreen(p, mode, true, {}, {}, {}, {}, {}) } }
        return m
    }

    @Test fun everyPaletteRendersAndLooksDifferent() {
        val hashes = Palettes.all.map { p -> screens(p, dark = false, tag = "${p.id}-light")["chat"]!! }
        assertTrue(hashes.toSet().size == hashes.size, "each palette must change the pixels")
        Palettes.all.forEach { screens(it, dark = true, tag = "${it.id}-dark") }
    }

    @Test fun otherScreens() {
        val p = Palettes.DEFAULT
        render("fern-light-unlock") { NerdTheme(p, DarkMode.Light) { androidx.compose.material3.Surface(color = androidx.compose.material3.MaterialTheme.colorScheme.background) { UnlockScreen(false) {} } } }
        render("fern-dark-unlock") { NerdTheme(p, DarkMode.Dark) { androidx.compose.material3.Surface(color = androidx.compose.material3.MaterialTheme.colorScheme.background) { UnlockScreen(false) {} } } }
        val offer = FakeBackend().createPairingOffer()
        render("fern-light-pair") { NerdTheme(p, DarkMode.Light) { PairScreen({ offer }, { _, _ -> JoinResult.Rejected("x") }, {}, {}, 0, offer) } }
        render("fern-light-pair-join") { NerdTheme(p, DarkMode.Light) { PairScreen({ offer }, { _, _ -> JoinResult.Rejected("x") }, {}, {}, 1) } }
        render("fern-light-details") { NerdTheme(p, DarkMode.Light) { DetailsScreen(contact(3), {}, {}) } }
        render("fern-light-details-verified") { NerdTheme(p, DarkMode.Light) { DetailsScreen(contact(1), {}, {}) } }
        render("fern-light-empty") { NerdTheme(p, DarkMode.Light) { ChatListScreen(emptyList(), TorState.Off, false, {}, {}, {}) } }
    }

    @Test fun fullAppFlowUnlocksAndPanicsBackToTheLockScreen() {
        val b = FakeBackend()
        var exited = false
        val locked = render("flow-1-locked") { NerdApp(b, Palettes.DEFAULT, DarkMode.Light, onExit = { exited = true }) }
        b.unlock("pw".toCharArray())
        val after = render("flow-2-unlocked-state") { NerdApp(b, Palettes.DEFAULT, DarkMode.Light, startAt = 0) }
        assertNotEquals(locked, after)
        b.panic()
        assertTrue(b.panicked && b.state.value == AppState())
    }
}
