package app.nerdchat.model

import kotlinx.coroutines.flow.StateFlow

/**
 * The contract between the Kotlin screens and the Rust core. [RustBackend] talks to the real core through JNI; [FakeBackend] stands in
 * for previews, screenshots and demo builds.
 *
 * EVERYTHING IS STATE-DRIVEN: a call returns at once and the result shows up in [state] (the core derives keys on a worker thread,
 * pairing waits for Tor, a message is confirmed seconds later). Never wait for a call, observe the state.
 *
 * Rules every implementation must keep:
 *  * secrets arrive as `CharArray` and the implementation wipes them; a line of chat arrives as `String` (known gap G1);
 *  * nothing here ever returns a timestamp, a read state or a typing state, because the core has none.
 */
interface ChatBackend {
    val state: StateFlow<AppState>

    /**
     * One password step. Which step it is depends on [AppState.stage]: unlock (the vault exists), choose a password (first run, minimum 12
     * characters) or repeat it. The array is wiped before this returns.
     */
    fun submitPassword(password: CharArray)

    /** Panic: wipe memory and leave. The host process ends right after. */
    fun panic()

    /** Purge: like [panic] and also overwrite and delete the vault and everything exported. */
    fun purge()

    fun setOnline(online: Boolean)

    /** Select a contact and open the conversation with it (clears its unread counter). */
    fun open(contactId: Int)

    /** Leave the conversation (back to the list). */
    fun closeChat()

    fun send(contactId: Int, text: String)

    // --- pairing over Tor ---
    /** Create a contact with a fresh key pair (it has no peer yet) and select it. */
    fun addContact(name: String)

    /** Offer a pairing for the selected contact: [AppState.torOffer] appears when Tor has published the service. */
    fun startOffer()

    /** Join a pairing: the link by any channel, the code (10 digits, said aloud) as a secret. The array is wiped. */
    fun joinWithLink(link: String, code: CharArray)

    fun cancelPairing()

    /** Answer the question that appears when [AppState.pairingWaiting]: did you exchange the code in person? */
    fun answerInPerson(inPerson: Boolean)

    // --- verification ---
    /** Select the contact and open the safety-number comparison: [AppState.verifyNumber] appears. */
    fun startVerify(contactId: Int)

    fun confirmVerify(matches: Boolean)

    fun acknowledgeAlert()

    /**
     * The ENCRYPTED OUTBOX. On: a message the contact has not confirmed yet is written to the password-locked vault and sent again on every new connection
     * until it is confirmed, so it survives a restart or the OS killing the app, and can even be typed while offline. Off: messages exist only in memory.
     * Costs: the vault file changes whenever a message is sent or confirmed, and an old copy of a removed message may stay in flash memory.
     */
    fun setKeepOutbox(keep: Boolean)
}
