package app.nerdchat.model

import kotlinx.coroutines.flow.StateFlow

/**
 * The contract between the Kotlin screens and the Rust core. The real implementation (JNI over `nerd-chat-app`, phase P2/P3 of
 * docs/ANDROID_PORT.md) is not written yet: [FakeBackend] stands in so the whole UI can be built and reviewed first.
 *
 * Rules every implementation must keep:
 *  * secrets (the password) arrive as `CharArray` and the implementation wipes them; a line of chat arrives as `CharArray` too
 *    (the current screens still pass `String` for the draft: known gap G1, see android/README.md);
 *  * nothing here ever returns a timestamp, a read state or a typing state, because the core has none.
 */
interface ChatBackend {
    val state: StateFlow<AppState>

    /** Try to open the vault. The array is wiped before this returns. */
    fun unlock(password: CharArray): Boolean

    /** Panic: wipe memory and leave. The host process ends right after. */
    fun panic()

    /** Purge: like [panic] and also overwrite and delete the vault and everything exported. */
    fun purge()

    fun setOnline(online: Boolean)

    fun send(contactId: Int, text: String)

    /** Opening a chat clears its unread counter. */
    fun open(contactId: Int)

    fun createPairingOffer(): PairingOffer

    fun join(link: String, code: String): JoinResult

    fun markVerified(contactId: Int)
}
