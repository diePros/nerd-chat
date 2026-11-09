@file:OptIn(androidx.compose.ui.InternalComposeUiApi::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package app.sineloco.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import app.sineloco.model.*
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
    private val ready = demo.copy(stage = Stage.Ready, online = true, tor = TorState.Ready)

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
        m["list"] = render("$tag-list") { SineTheme(p, mode) { ChatListScreen(demo.chats, TorState.Ready, true, {}, {}, {}) } }
        m["chat"] = render("$tag-chat") { SineTheme(p, mode) { ChatScreen(contact(0), demo.messages[0]!!, TorState.Ready, true, {}, {}, {}) } }
        m["unverified"] = render("$tag-chat-unverified") { SineTheme(p, mode) { ChatScreen(contact(1), demo.messages[1]!!, TorState.Ready, true, {}, {}, {}) } }
        m["settings"] = render("$tag-settings") { SineTheme(p, mode) { SettingsScreen(p, mode, true, TorState.Ready, Persist.Day, {}, {}, {}, {}, {}, {}) } }
        return m
    }

    @Test fun everyPaletteRendersAndLooksDifferent() {
        val hashes = Palettes.all.map { p -> screens(p, dark = false, tag = "${p.id}-light")["chat"]!! }
        assertTrue(hashes.toSet().size == hashes.size, "each palette must change the pixels")
        Palettes.all.forEach { screens(it, dark = true, tag = "${it.id}-dark") }
    }

    @Test fun otherScreens() {
        val p = Palettes.DEFAULT
        fun lock(stage: Stage, status: String = "", err: Boolean = false) = render("fern-light-${stage.name.lowercase()}") { SineTheme(p, DarkMode.Light) { Surface(color = MaterialTheme.colorScheme.background) { UnlockScreen(stage, status, err) {} } } }
        render("fern-light-unlock") { SineTheme(p, DarkMode.Light) { Surface(color = MaterialTheme.colorScheme.background) { UnlockScreen(Stage.Unlock, "", false) {} } } }
        render("fern-dark-unlock") { SineTheme(p, DarkMode.Dark) { Surface(color = MaterialTheme.colorScheme.background) { UnlockScreen(Stage.Unlock, "", false) {} } } }
        lock(Stage.CreatePassword, "Too short: use at least 12 characters (a long passphrase).", true)
        lock(Stage.ConfirmPassword, "Repeat the password.")
        lock(Stage.Working)
        val offer = TorOffer("sineloco:pair/mxqfz3k7ayv2wbn5cdr4eh6jg2tup7lis3o5kqwn4yz6ahbvc3dfe6xi", "4821-7390-52", 299, "Sam")
        render("fern-light-pair") { SineTheme(p, DarkMode.Light) { PairScreen(ready.copy(torOffer = offer), FakeBackend(), NoPlatform, 0) } }
        render("fern-light-pair-name") { SineTheme(p, DarkMode.Light) { PairScreen(ready, FakeBackend(), NoPlatform, 0) } }
        render("fern-light-pair-join") { SineTheme(p, DarkMode.Light) { PairScreen(ready.copy(status = "That link is not a Sine Loco link.", statusIsError = true), FakeBackend(), NoPlatform, 1) } }
        render("fern-light-pair-text") { SineTheme(p, DarkMode.Light) { PairScreen(ready.copy(exportText = "-----BEGIN SINE LOCO CONTACT-----\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4\n-----END SINE LOCO CONTACT-----"), FakeBackend(), object : PlatformActions { override fun lanAddresses() = listOf("192.168.1.5") }, 2) } }
        render("fern-light-pair-lan") { SineTheme(p, DarkMode.Light) { PairScreen(ready.copy(lanOffer = app.sineloco.model.LanOffer("192.168.1.5:40123", "4821739052", 290)), FakeBackend(), object : PlatformActions { override fun lanAddresses() = listOf("192.168.1.5", "10.0.0.7") }, 3) } }
        render("fern-light-qr") { SineTheme(p, DarkMode.Light) { Surface(color = MaterialTheme.colorScheme.background) { QrCode(app.sineloco.model.PairLink.torQr("sineloco:pair/mxqfz3k7ayv2wbn5cdr4eh6jg2tup7lis3o5kqwn4yz6ahbvc3dfe6xi", "4821-7390-52"), 300.dp) } } }
        render("fern-light-details") { SineTheme(p, DarkMode.Light) { DetailsScreen(contact(1), null, {}, {}, {}) } }
        render("fern-light-details-verify") { SineTheme(p, DarkMode.Light) { DetailsScreen(contact(1), "48213 07791 36502 91844 20365 77018", {}, {}, {}) } }
        render("fern-light-details-verified") { SineTheme(p, DarkMode.Light) { DetailsScreen(contact(0), null, {}, {}, {}) } }
        render("fern-light-chat-offline-outbox") { SineTheme(p, DarkMode.Light) {
            ChatScreen(contact(0), demo.messages[0]!! + Message(99, true, "Writing this while offline: it waits, encrypted.", Delivery.Queued), TorState.Off, false, {}, {}, {}, persist = Persist.Day) } }
        render("fern-dark-settings-outbox") { SineTheme(p, DarkMode.Dark) { SettingsScreen(p, DarkMode.Dark, true, TorState.Ready, Persist.Day, {}, {}, {}, {}, {}, {}) } }
        render("fern-light-empty") { SineTheme(p, DarkMode.Light) { ChatListScreen(emptyList(), TorState.Off, false, {}, {}, {}) } }
    }

    @Test fun fullAppFlowFromLockToChatListToWipe() {
        val b = FakeBackend()
        var exited = false
        val locked = render("flow-1-locked") { SineApp(b, Palettes.DEFAULT, DarkMode.Light, onExit = { exited = true }) }
        b.submitPassword("pw".toCharArray())
        val after = render("flow-2-unlocked") { SineApp(b, Palettes.DEFAULT, DarkMode.Light, onExit = { exited = true }) }
        assertNotEquals(locked, after, "unlocking changes the screen")
        b.panic()
        render("flow-3-wiped") { SineApp(b, Palettes.DEFAULT, DarkMode.Light, onExit = { exited = true }) }
        assertTrue(exited, "a wiped state ends the process")
    }

    @Test fun firstRunShowsTheCreateStepsAndAPairingQuestionDialog() {
        val b = FakeBackend(hasVault = false)
        val s1 = render("flow-first-1") { SineApp(b, Palettes.DEFAULT, DarkMode.Light) }
        b.submitPassword("a long enough passphrase".toCharArray())
        val s2 = render("flow-first-2") { SineApp(b, Palettes.DEFAULT, DarkMode.Light) }
        assertNotEquals(s1, s2, "the confirm step looks different")
        b.submitPassword("a long enough passphrase".toCharArray())
        b.addContact("Sam"); b.joinWithLink("sineloco:pair/" + "a".repeat(56), "4821739052".toCharArray())
        val s3 = render("flow-first-3-inperson") { SineApp(b, Palettes.DEFAULT, DarkMode.Light) }
        assertNotEquals(s2, s3)
        assertTrue(b.state.value.pairingWaiting)
    }
}
