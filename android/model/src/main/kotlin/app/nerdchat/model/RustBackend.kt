package app.nerdchat.model

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.Executors

/**
 * [ChatBackend] over the Rust core. ALL calls into the core run on ONE thread (the core is single-threaded by design); a ticker polls it
 * (the key derivation, Tor start, incoming messages and confirmations all arrive by polling) and every answer replaces [state].
 */
class RustBackend(
    private val native: Native, vaultDir: String, lowMem: Boolean, torPath: String?, keepOutboxDefault: Boolean,
    private val pollMillis: Long = 250, private val pollMillisBusy: Long = 80,
) : ChatBackend {
    private val thread = Executors.newSingleThreadExecutor { Thread(it, "nerdchat-core").apply { isDaemon = true } }
    private val dispatcher = thread.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val s = MutableStateFlow(Snapshot.parse(native.init(vaultDir, lowMem, torPath, keepOutboxDefault)))
    override val state: StateFlow<AppState> = s

    @Volatile private var closed = false

    init {
        scope.launch {
            while (isActive && !closed) {
                val st = s.value
                delay(if (st.stage == Stage.Working || st.tor is TorState.Bootstrapping) pollMillisBusy else pollMillis)
                if (st.stage == Stage.Wiped) continue
                s.value = Snapshot.parse(native.call("snapshot", null))
            }
        }
    }

    /** Run one op on the core thread and publish the answer. The argument array is wiped afterwards, whatever happens. */
    private fun op(name: String, arg: CharArray? = null, vararg more: Pair<String, CharArray?>) {
        scope.launch {
            try {
                var json = native.call(name, arg)
                for ((n, a) in more) { json = native.call(n, a) }
                s.value = Snapshot.parse(json)
            } finally {
                arg?.fill('\u0000')
                more.forEach { it.second?.fill('\u0000') }
            }
        }
    }

    private fun text(v: String) = v.toCharArray()

    override fun submitPassword(password: CharArray) = op("secret", password, "enter" to null)
    override fun panic() { op("panic") }
    override fun purge() { op("purge") }
    override fun setOnline(online: Boolean) = op("online", text(if (online) "1" else "0"))
    override fun open(contactId: Int) = op("select", text(contactId.toString()), "open_chat" to null)
    override fun closeChat() = op("back")
    override fun send(contactId: Int, text: String) = op("send", text(text))
    override fun addContact(name: String) = op("cmd", text("n"), "submit" to text(name))
    override fun startOffer() = op("cmd", text("T"))
    override fun joinWithLink(link: String, code: CharArray) = op("cmd", text("J"), "submit" to text(link.trim()), "secret" to code, "enter" to null)
    override fun cancelPairing() = op("cmd", text("x"))
    override fun answerInPerson(inPerson: Boolean) = op("in_person", text(if (inPerson) "1" else "0"))
    override fun startVerify(contactId: Int) = op("select", text(contactId.toString()), "cmd" to text("v"))
    override fun confirmVerify(matches: Boolean) = op("verify", text(if (matches) "1" else "0"))
    override fun acknowledgeAlert() = op("ack_alert")
    override fun setKeepOutbox(keep: Boolean) = op("keep_outbox", text(if (keep) "1" else "0"))

    /** Stop polling (tests, process end). The core itself ends with the process. */
    fun close() { closed = true; scope.cancel(); thread.shutdown() }
}
