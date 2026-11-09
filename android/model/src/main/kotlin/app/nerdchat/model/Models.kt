package app.nerdchat.model

/**
 * What a sent line shows. There are NO read receipts, no typing indicators and no timestamps in this app, by design (docs/DELIVERY.md):
 * [Delivered] means "their app has it", not "they read it", and it is drawn in the palette colour, never in WhatsApp-blue.
 */
enum class Delivery { Queued, Delivered, Refused }

data class Message(val id: Long, val fromMe: Boolean, val text: String, val delivery: Delivery? = null)

/** State of the link to one contact. */
enum class Link { Connected, Connecting, Offline }

data class Contact(
    val id: Int,
    val name: String,
    val verified: Boolean,
    val link: Link,
    /** the safety number as groups of digits, shown in the details screen to compare in person or by phone */
    val safetyNumber: List<String>,
    val onionShort: String,
    /** we host this contact's onion service while online, or only dial */
    val weHost: Boolean,
)

data class ChatSummary(val contact: Contact, val preview: String?, val unread: Int)

sealed interface TorState {
    data object Off : TorState
    data class Bootstrapping(val percent: Int) : TorState
    data object Ready : TorState
    data class Failed(val reason: String) : TorState
}

data class AppState(
    val unlocked: Boolean = false,
    val tor: TorState = TorState.Off,
    /** the user wants to be reachable (service running); false = offline on purpose */
    val online: Boolean = false,
    val chats: List<ChatSummary> = emptyList(),
    val messages: Map<Int, List<Message>> = emptyMap(),
)

/** What the user shows or reads when pairing over Tor: a link (any channel) and a code (a DIFFERENT channel). */
data class PairingOffer(val link: String, val code: String, val expiresInSeconds: Int)

sealed interface JoinResult {
    data class Paired(val contactId: Int) : JoinResult
    data class Rejected(val reason: String) : JoinResult
}
