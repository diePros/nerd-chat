package app.sineloco.model

import kotlinx.coroutines.flow.StateFlow

/**
 * The contract between the Kotlin screens and the Rust core. [RustBackend] talks to the real core through JNI; [FakeBackend] stands in
 * for previews, screenshots and demo builds.
 *
 * EVERYTHING IS STATE-DRIVEN: a call returns at once and the result shows up in [state] (the core derives keys on a worker thread,
 * pairing waits for Tor, a message is confirmed seconds later). Never wait for a call, observe the state.
 *
 * Rules every implementation must keep:
 *  * secrets arrive as `CharArray` and the implementation wipes them (after the call has been handed to the core's thread: a call that never started, for example because the backend was closed, does not); a line of chat arrives as `String` (known gap G1);
 *  * nothing here ever returns a timestamp, a read state or a typing state, because the core has none.
 */
interface ChatBackend {
    val state: StateFlow<AppState>

    /**
     * One password step. Which step it is depends on [AppState.stage]: unlock (the vault exists), choose a password (first run, minimum 12
     * characters) or repeat it. The array is wiped once the core thread has used it (not necessarily before this returns).
     */
    fun submitPassword(password: CharArray)

    /** Panic: wipe memory and leave. The host process ends right after. */
    fun panic()

    /** The way out for a user in a hurry (notification button, lock screen): offline NOW, no password, no question; a tor that is still starting is cancelled. */
    fun goOfflineNow()

    /** The phone's network went away (`false`) or came back (`true`): with it gone tor's network is switched off, coming back is delayed by a random few seconds. */
    fun networkChanged(up: Boolean) {}

    /**
     * Pairing by contact TEXT (the contact file, shared or pasted instead of saved as a file). [exportMine]: show my text, for a NEW contact called [newName], or (null) for the contact
     * that is selected now; the result arrives as [AppState.exportText]. [importTheirs]: add the other person's text, to a new contact or (null) the selected one.
     */
    fun exportMine(newName: String?) {}
    fun clearExport() {}
    fun importTheirs(newName: String?, theirs: String) {}

    /** Pairing on the LOCAL network (a direct connection, private addresses only): offer (result in [AppState.lanOffer]) or join with the other device's address and code. */
    fun lanOffer(newName: String?, addr: String) {}
    fun lanJoin(newName: String?, addr: String, code: CharArray) {}

    /** Forget the keys of a contact (and give it fresh keys of our own) so that it can be paired AGAIN; name and conversation stay. For a pairing that only finished on one side. The caller has asked the user to confirm. */
    fun repairContact(contactId: Int) {}

    /** Throw away a finished pairing without saving it (the other side did not finish). Answer of the in-person question, third choice. */
    fun discardPairing() {}

    /** Delete a contact and everything kept about it (keys, conversation, history). The caller has already asked the user to confirm. */
    fun deleteContact(contactId: Int) {}

    /** Ask the core for the current state without changing anything: the first thing every call does is the lock's deadline check, so this is how a wake-up makes a timed-out lock erase itself before anything is shown. */
    fun refresh() {}

    /** A real lock: the app keeps running (tor, messages arrive) but shows only the password prompt ([Stage.Unlock] with [AppState.locked]) and the core hands out no contact or message data until the password is typed again. */
    fun lock()

    /** [panic], but waits (at most [timeoutMillis]) until the core has wiped: for the last moments of the process (swipe-away, exit), where an asynchronous call would be killed unfinished. */
    fun panicBlocking(timeoutMillis: Long = 700) { panic() }

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
     * What is kept on the device: nothing, only unconfirmed outgoing texts, or everything for about a day or a week (encrypted in a separate history file that is written only on a
     * fixed 5-second clock, so its file times never show when a message was sent). Kept texts survive a restart or the OS killing the app, and can be typed while offline.
     * Costs: anyone with the device and the password can read what is kept, and a deleted message may survive in the phone's storage.
     */
    fun setPersist(persist: Persist)
}
