package app.sineloco.model

/**
 * What a sent line shows. There are NO read receipts, no typing indicators and no timestamps in this app, by design (docs/DELIVERY.md):
 * [Delivered] means "their app has it", not "they read it", and it is drawn in the palette colour, never in WhatsApp-blue.
 */
enum class Delivery {
    /** written, the contact's app has not confirmed it yet (it is resent on every new connection) */
    Queued,
    /** we went offline while it was unconfirmed: it may or may not have arrived */
    Unconfirmed,
    Delivered,
    /** the core refused the text (outbox full, too long): it was not sent and never will be */
    Refused,
}

data class Message(val id: Long, val fromMe: Boolean, val text: String, val delivery: Delivery? = null)

/** State of the link to one contact. */
enum class Link { Connected, Connecting, Offline }

/** How sure we are who this contact is (the core's three levels). */
enum class Trust { Unverified, Code, Verified }

data class Contact(
    /** the position in the contact list (the core addresses contacts by position) */
    val id: Int,
    val name: String,
    val trust: Trust,
    /** false until pairing gave us the contact's keys */
    val paired: Boolean,
    val link: Link,
    /** the safety number as groups of digits (only known for the contact the core has selected; empty otherwise) */
    val safetyNumber: List<String>,
    /** shortened onion address, empty when the core does not tell */
    val onionShort: String,
    /** we host this contact's onion service while online, or only dial */
    val weHost: Boolean,
) {
    val verified: Boolean get() = trust == Trust.Verified
}

data class ChatSummary(val contact: Contact, val preview: String?, val unread: Int)

sealed interface TorState {
    data object Off : TorState
    data class Bootstrapping(val percent: Int) : TorState
    data object Ready : TorState
    data class Failed(val reason: String) : TorState
}

/** Where the app is in its life: the lock screen, the vault creation steps, working (key derivation), the main app, or wiped. */
enum class Stage { Unlock, CreatePassword, ConfirmPassword, Working, Ready, Wiped, Error }

/** The link and code of an open pairing offer over Tor: the link goes to the partner by any channel, the code by a DIFFERENT one. */
data class TorOffer(val link: String, val code: String, val expiresInSeconds: Int, val forContact: String?)

/**
 * What is kept on the device. [Off]: messages exist only in memory. [Outbox]: only texts we sent that the contact has not confirmed yet. [Day] / [Week]: every message, deleted after
 * about a day (24-30 h) or a week. Deletion is best effort: see docs/HISTORY_AND_TIMING_PLAN.md.
 */
enum class Persist { Off, Outbox, Day, Week }

data class AppState(
    val stage: Stage = Stage.Unlock,
    /** the app is LOCKED (not a first unlock): it still runs underneath, the screen is the password prompt */
    val locked: Boolean = false,
    /** the core's status line, shown under the password field and in banners */
    val status: String = "",
    val statusIsError: Boolean = false,
    /** how many password characters the core holds (the dots); the characters themselves never come back */
    val pwChars: Int = 0,
    val tor: TorState = TorState.Off,
    /** the user wants to be reachable (Tor running or starting); false = offline on purpose */
    val online: Boolean = false,
    /** the user chose offline (not a failure): nothing may keep the app running or reachable */
    val userOffline: Boolean = false,
    val chats: List<ChatSummary> = emptyList(),
    /** lines of the OPEN chat only (the core keeps nothing else on screen), keyed by contact id */
    val messages: Map<Int, List<Message>> = emptyMap(),
    val torOffer: TorOffer? = null,
    /** a pairing finished and waits for "did you exchange the code in person?" */
    val pairingWaiting: Boolean = false,
    /** the safety number shown while comparing (verification open) */
    val verifyNumber: String? = null,
    /** security warnings from the engine, until acknowledged */
    val alerts: List<String> = emptyList(),
    /** why the last command was refused by the bridge's guards (None: accepted) */
    val rejected: String? = null,
    /** what is kept on the device (the core's effective setting: the user's choice, else the phone's default) */
    val persist: Persist = Persist.Off,
    /** the core has a text prompt open (a half-finished step): the backend closes it when a step of a chain was refused */
    val promptOpen: Boolean = false,
)
