package app.sineloco.model

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * In-memory stand-in for the Rust core: demo contacts, instant behaviour, no timers (call [confirmQueued] to simulate the contacts' apps
 * confirming). The first run has no vault: with `seed = true` the demo opens with any password of at least 12 characters (the same rule
 * as the core), with any shorter one it explains why not. Used by previews, screenshot tests and demo builds.
 */
class FakeBackend(seed: Boolean = true, private val hasVault: Boolean = true, persist: Persist = Persist.Off) : ChatBackend {
    private val s = MutableStateFlow(
        (if (seed) demoState() else AppState()).copy(stage = if (hasVault) Stage.Unlock else Stage.CreatePassword,
            status = (if (hasVault) "DEMO BUILD, no real vault. Enter any password." else "DEMO BUILD, no real vault. Creating a NEW one (min 12 characters)."), persist = persist))
    override val state: StateFlow<AppState> = s
    private var nextId = 100L
    private var firstPw: String? = null
    private var pendingContact: Contact? = null
    private var verifyFor: Int? = null
    var panicked = false; private set
    var purged = false; private set

    private fun contacts() = s.value.chats

    override fun submitPassword(password: CharArray) {
        val pw = String(password); password.fill('\u0000')
        when (s.value.stage) {
            Stage.Unlock -> if (pw.isNotEmpty()) s.update { it.copy(stage = Stage.Ready, online = true, tor = TorState.Ready, status = "Unlocked.", statusIsError = false) }
                else s.update { it.copy(status = "Wrong password or keyfile.", statusIsError = true) }
            Stage.CreatePassword -> if (pw.length < 12) s.update { it.copy(status = "Too short: use at least 12 characters (a long passphrase).", statusIsError = true) }
                else { firstPw = pw; s.update { it.copy(stage = Stage.ConfirmPassword, status = "Repeat the password.", statusIsError = false) } }
            Stage.ConfirmPassword -> if (pw == firstPw) s.update { it.copy(stage = Stage.Ready, online = true, tor = TorState.Ready, status = "Vault created.", statusIsError = false) }
                else { firstPw = null; s.update { it.copy(stage = Stage.CreatePassword, status = "Passwords did not match. Start again.", statusIsError = true) } }
            else -> {}
        }
    }

    override fun panic() { panicked = true; s.value = AppState(stage = Stage.Wiped) }
    override fun purge() { purged = true; s.value = AppState(stage = Stage.Wiped) }

    override fun setOnline(online: Boolean) {
        s.update { it.copy(online = online, tor = if (online) TorState.Ready else TorState.Off) }
    }

    override fun open(contactId: Int) {
        s.update { st -> st.copy(chats = st.chats.map { if (it.contact.id == contactId) it.copy(unread = 0) else it }) }
    }

    override fun closeChat() {}

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

    override fun addContact(name: String) {
        val n = name.trim()
        if (n.isEmpty()) { s.update { it.copy(status = "A contact needs a name.", statusIsError = true) }; return }
        val c = Contact(contacts().size, n, Trust.Unverified, false, Link.Offline, emptyList(), "", false)
        pendingContact = c
        s.update { it.copy(chats = it.chats + ChatSummary(c, null, 0), status = "Contact created with a NEW keypair.", statusIsError = false) }
    }

    override fun startOffer() {
        val c = pendingContact ?: return
        s.update { it.copy(torOffer = TorOffer("sineloco:pair/mxqfz3k7ayv2wbn5cdr4eh6jg2tup7lis3o5kqwn4yz6ahbvc3dfe6xi", "4821-7390-52", 300, c.name)) }
    }

    override fun joinWithLink(link: String, code: CharArray) {
        val digits = code.count { it.isDigit() }; code.fill('\u0000')
        val id = link.trim().lowercase().removePrefix("sineloco:pair/").removeSuffix(".onion")
        when {
            id.length != 56 -> s.update { it.copy(status = "That link is not a Sine Loco link (56 characters expected).", statusIsError = true) }
            digits != 10 -> s.update { it.copy(status = "The code has 10 digits.", statusIsError = true) }
            else -> s.update { it.copy(pairingWaiting = true, status = "Pairing finished: answer the in-person question.", statusIsError = false) }
        }
    }

    override fun cancelPairing() { s.update { it.copy(torOffer = null, pairingWaiting = false) } }

    override fun answerInPerson(inPerson: Boolean) {
        val trust = if (inPerson) Trust.Code else Trust.Unverified
        s.update { st ->
            val last = st.chats.lastOrNull()
            st.copy(pairingWaiting = false, torOffer = null,
                chats = if (last == null) st.chats else st.chats.dropLast(1) + last.copy(contact = last.contact.copy(paired = true, trust = trust, link = Link.Connecting)))
        }
    }

    override fun startVerify(contactId: Int) {
        val c = contacts().firstOrNull { it.contact.id == contactId }?.contact ?: return
        verifyFor = contactId
        s.update { it.copy(verifyNumber = c.safetyNumber.joinToString(" ").ifEmpty { "48213 07791 36502 91844 20365 77018" }) }
    }

    override fun confirmVerify(matches: Boolean) {
        val id = verifyFor; verifyFor = null
        s.update { st ->
            if (!matches || id == null) st.copy(verifyNumber = null, status = "Not verified.", statusIsError = false)
            else st.copy(verifyNumber = null, status = "Verified: this contact's identity is confirmed.", statusIsError = false,
                chats = st.chats.map { if (it.contact.id == id) it.copy(contact = it.contact.copy(trust = Trust.Verified)) else it })
        }
    }

    override fun acknowledgeAlert() { s.update { it.copy(alerts = it.alerts.drop(1)) } }

    override fun setPersist(persist: Persist) { s.update { it.copy(persist = persist) } }

    companion object {
        private val SAFETY = listOf("48213", "07791", "36502", "91844", "20365", "77018")
        private fun c(id: Int, name: String, t: Trust, l: Link, host: Boolean) = Contact(id, name, t, true, l, SAFETY.map { it.reversed() }, "k${id}mx4qz…", host)

        fun demoState(): AppState {
            val mira = c(0, "Mira", Trust.Verified, Link.Connected, true)
            val li = c(1, "Aunt Li", Trust.Unverified, Link.Connected, false)
            val jonas = c(2, "Jonas", Trust.Verified, Link.Offline, false)
            val kofi = c(3, "Kofi", Trust.Verified, Link.Connecting, true)
            return AppState(
                stage = Stage.Unlock, tor = TorState.Off, online = false,
                chats = listOf(
                    ChatSummary(mira, "Same place as last time?", 2),
                    ChatSummary(li, "You: ok, I will check the code tonight", 0),
                    ChatSummary(jonas, "You: see you thursday", 0),
                    ChatSummary(kofi, null, 0),
                ),
                messages = mapOf(
                    0 to listOf(
                        Message(1, false, "Did the new phone arrive?"),
                        Message(2, true, "Yes. Everything is set up, I used the short code like we agreed.", Delivery.Delivered),
                        Message(3, false, "Good. Nobody saw us exchanging it."),
                        Message(4, true, "Not a soul.", Delivery.Delivered),
                        Message(5, false, "Same place as last time?"),
                        Message(6, false, "Bring the grey bag."),
                    ),
                    1 to listOf(
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
