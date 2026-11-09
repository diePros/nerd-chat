package app.nerdchat.model

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * In-memory stand-in for the Rust core: demo contacts, instant "unlock" with any non-empty password, deterministic behaviour (no timers:
 * call [confirmQueued] to simulate the contacts' apps confirming). Used by the previews, the screenshot tests and the first device runs.
 */
class FakeBackend(seed: Boolean = true) : ChatBackend {
    private val s = MutableStateFlow(if (seed) demoState() else AppState())
    override val state: StateFlow<AppState> = s
    private var nextId = 100L
    var panicked = false; private set
    var purged = false; private set

    override fun unlock(password: CharArray): Boolean {
        val ok = password.isNotEmpty()
        password.fill('\u0000')
        if (ok) s.update { it.copy(unlocked = true, online = true, tor = TorState.Ready) }
        return ok
    }

    override fun panic() { panicked = true; s.value = AppState() }
    override fun purge() { purged = true; s.value = AppState() }

    override fun setOnline(online: Boolean) {
        s.update { it.copy(online = online, tor = if (online) TorState.Ready else TorState.Off) }
    }

    override fun send(contactId: Int, text: String) {
        val t = text.trim()
        if (t.isEmpty()) return
        s.update { st ->
            val list = st.messages[contactId].orEmpty() + Message(nextId++, true, t, Delivery.Queued)
            st.copy(messages = st.messages + (contactId to list), chats = st.chats.map { if (it.contact.id == contactId) it.copy(preview = "You: $t") else it })
        }
    }

    /** Simulate the contacts' apps confirming every queued line of a CONNECTED contact. */
    fun confirmQueued() {
        s.update { st ->
            val up = st.chats.filter { it.contact.link == Link.Connected }.map { it.contact.id }.toSet()
            st.copy(messages = st.messages.mapValues { (id, l) -> if (id in up) l.map { if (it.delivery == Delivery.Queued) it.copy(delivery = Delivery.Delivered) else it } else l })
        }
    }

    override fun open(contactId: Int) {
        s.update { st -> st.copy(chats = st.chats.map { if (it.contact.id == contactId) it.copy(unread = 0) else it }) }
    }

    override fun createPairingOffer() = PairingOffer(
        link = "nerdchat:pair/" + "mxqfz3k7ayv2wbn5cdr4eh6jg2tup7lis3o5kqwn4yz6ahbvc3dfe6xi",
        code = "4821-7390-52", expiresInSeconds = 300,
    )

    override fun join(link: String, code: String): JoinResult {
        val id = link.trim().lowercase().removePrefix("nerdchat:pair/").removeSuffix(".onion")
        if (id.length != 56) return JoinResult.Rejected("That link is not a Nerd-chat link (56 characters expected).")
        if (code.filter { it.isDigit() }.length != 10) return JoinResult.Rejected("The code has 10 digits.")
        val c = Contact(nextId.toInt(), "New contact", false, Link.Connecting, SAFETY, id.take(8) + "…", false)
        nextId++
        s.update { it.copy(chats = it.chats + ChatSummary(c, null, 0)) }
        return JoinResult.Paired(c.id)
    }

    override fun markVerified(contactId: Int) {
        s.update { st -> st.copy(chats = st.chats.map { if (it.contact.id == contactId) it.copy(contact = it.contact.copy(verified = true)) else it }) }
    }

    companion object {
        private val SAFETY = listOf("48213", "07791", "36502", "91844", "20365", "77018")
        private fun c(id: Int, name: String, v: Boolean, l: Link, host: Boolean) = Contact(id, name, v, l, SAFETY.map { it.reversed() }, "k${id}mx4qz…", host)

        fun demoState(): AppState {
            val mira = c(1, "Mira", true, Link.Connected, true)
            val jonas = c(2, "Jonas", true, Link.Offline, false)
            val li = c(3, "Aunt Li", false, Link.Connected, false)
            val kofi = c(4, "Kofi", true, Link.Connecting, true)
            return AppState(
                unlocked = false, tor = TorState.Off, online = false,
                chats = listOf(
                    ChatSummary(mira, "Same place as last time?", 2),
                    ChatSummary(li, "You: ok, I will check the code tonight", 0),
                    ChatSummary(jonas, "You: see you thursday", 0),
                    ChatSummary(kofi, null, 0),
                ),
                messages = mapOf(
                    1 to listOf(
                        Message(1, false, "Did the new phone arrive?"),
                        Message(2, true, "Yes. Everything is set up, I used the short code like we agreed.", Delivery.Delivered),
                        Message(3, false, "Good. Nobody saw us exchanging it."),
                        Message(4, true, "Not a soul.", Delivery.Delivered),
                        Message(5, false, "Same place as last time?"),
                        Message(6, false, "Bring the grey bag."),
                    ),
                    3 to listOf(
                        Message(10, false, "Is this the right app? My grandson installed it."),
                        Message(11, true, "Yes! Please check the number code with me when we talk.", Delivery.Delivered),
                        Message(12, true, "ok, I will check the code tonight", Delivery.Queued),
                    ),
                    2 to listOf(Message(20, true, "see you thursday", Delivery.Queued)),
                ),
            )
        }
    }
}
