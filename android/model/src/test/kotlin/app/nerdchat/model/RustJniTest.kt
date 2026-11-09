package app.nerdchat.model

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.nio.file.Files
import kotlin.test.*

/**
 * END TO END through the REAL JNI: the host build of `libnerdchat_bridge.so` is loaded into this JVM and driven by the real [RustBackend]:
 * Kotlin -> JNI -> command layer -> the real core with a real vault on disk. It is the closest thing to the phone that exists without a phone
 * (same Kotlin, same JNI symbols, same Rust; only the CPU and libc differ). Skipped when the library was not built (`cargo build --release -p nerd-chat-android`).
 */
class RustJniTest {
    private val lib = System.getProperty("nerdchat.lib")?.let(::File)?.takeIf { it.isFile }
    private val pw = "correct horse battery staple"

    private fun backend(dir: File): RustBackend {
        NativeBridge.load(lib!!.absolutePath)
        return RustBackend(NativeBridge, dir.absolutePath, lowMem = true, torPath = null, pollMillis = 20, pollMillisBusy = 20)
    }

    private fun await(b: RustBackend, what: String, max: Long = 90_000, ok: (AppState) -> Boolean): AppState = runBlocking {
        val end = System.currentTimeMillis() + max
        while (System.currentTimeMillis() < end) { b.state.value.takeIf(ok)?.let { return@runBlocking it }; delay(20) }
        fail("timed out waiting for: $what; last state: ${b.state.value}")
    }

    @Test fun firstRunCreateUnlockPersistAndPanicThroughTheRealCore() {
        assumeTrue(lib != null, "host bridge library not built: cargo build --release -p nerd-chat-android")
        val dir = Files.createTempDirectory("nerdchat-jni").toFile()
        try {
            var b = backend(dir)
            assertEquals(Stage.CreatePassword, b.state.value.stage, "no vault yet: the core asks to create one")

            b.submitPassword("short".toCharArray())
            val tooShort = await(b, "refusal of a short password") { it.status.contains("Too short") }
            assertEquals(Stage.CreatePassword, tooShort.stage); assertEquals(0, tooShort.pwChars, "the refused password was cleared")

            b.submitPassword(pw.toCharArray()); await(b, "confirm step") { it.stage == Stage.ConfirmPassword }
            b.submitPassword(pw.toCharArray())
            val ready = await(b, "vault created and opened") { it.stage == Stage.Ready }
            assertTrue(ready.chats.isEmpty())

            // text with quotes, a backslash, accents and a non-BMP character crosses char[] -> UTF-16 decoding -> core -> JSON -> Kotlin intact
            val name = "A \"q\" \\ ü 😀"
            b.addContact(name)
            val withContact = await(b, "contact created") { it.chats.isNotEmpty() }
            val c = withContact.chats.single().contact
            assertEquals(name, c.name); assertFalse(c.paired); assertEquals(Trust.Unverified, c.trust)
            assertTrue(File(dir, "nerd-chat.vault").isFile, "the vault is on disk")

            b.panic()
            val wiped = await(b, "panic wipe") { it.stage == Stage.Wiped }
            assertTrue(wiped.chats.isEmpty())
            b.close()

            // a second start: the vault exists now, a wrong password is refused, the right one restores the contact
            b = backend(dir)
            assertEquals(Stage.Unlock, b.state.value.stage)
            b.submitPassword("a completely wrong password".toCharArray())
            val wrong = await(b, "wrong password refused") { it.stage == Stage.Unlock && it.statusIsError }
            assertTrue(wrong.status.contains("Wrong password"), wrong.status)
            b.submitPassword(pw.toCharArray())
            val again = await(b, "unlock") { it.stage == Stage.Ready }
            assertEquals(name, again.chats.single().contact.name, "the contact survived in the vault")

            // text goes only where the core takes text: asking for a chat that does not exist is refused by the bridge, not typed into the core
            b.send(0, "hello")
            val refused = await(b, "refusal") { it.rejected != null }
            assertEquals("open a chat first", refused.rejected)

            b.purge()
            await(b, "purge") { it.stage == Stage.Wiped }
            assertFalse(File(dir, "nerd-chat.vault").exists(), "purge deleted the vault")
            b.close()
        } finally { dir.deleteRecursively() }
    }
}
