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
    private val native: Native, vaultDir: String, lowMem: Boolean, torPath: String?, historyDefault: Persist, private val keys: PlatformKeys? = null,
    private val pollMillis: Long = 250, private val pollMillisBusy: Long = 80,
) : ChatBackend {
    private val thread = Executors.newSingleThreadExecutor { Thread(it, "nerdchat-core").apply { isDaemon = true } }
    private val dispatcher = thread.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val s = MutableStateFlow(Snapshot.parse(native.init(vaultDir, lowMem, torPath, historyDefault.ordinal, keys)))
    override val state: StateFlow<AppState> = s

    @Volatile private var closed = false
    private var lastMode: Persist? = null
    /** Tell the key store which history setting is in force (only a state of an UNLOCKED app tells the truth about it). */
    private fun track(a: AppState): AppState { if (a.stage == Stage.Ready && a.persist != lastMode) { lastMode = a.persist; (keys as? HistoryModeListener)?.modeChanged(a.persist) }; return a }

    /** the bridge's refusal text stays visible for a few seconds (the next poll answer carries none) */
    @Volatile private var latched: String? = null
    @Volatile private var latchedUntil = 0L
    private fun latch(text: String) { latched = text; latchedUntil = System.nanoTime() + 6_000_000_000L }
    private fun withLatch(a: AppState): AppState = if (a.rejected == null && latched != null && System.nanoTime() < latchedUntil) a.copy(rejected = latched) else a

    init {
        scope.launch {
            while (isActive && !closed) {
                val st = s.value
                delay(if (st.stage == Stage.Working || st.tor is TorState.Bootstrapping) pollMillisBusy else pollMillis)
                if (st.stage == Stage.Wiped) continue
                s.value = track(withLatch(Snapshot.parse(native.call("snapshot", null))))
            }
        }
    }

    /** Run one op on the core thread and publish the answer. The argument array is wiped afterwards, whatever happens. */
    private fun op(name: String, arg: CharArray? = null, vararg more: Pair<String, CharArray?>) {
        scope.launch {
            try {
                // A chain stops at the FIRST refused step: running the next step anyway could act on the wrong contact or type into a stale prompt.
                var parsed = Snapshot.parse(native.call(name, arg))
                var refused = parsed.rejected
                for ((n, a) in more) {
                    if (refused != null) break
                    parsed = Snapshot.parse(native.call(n, a))
                    refused = parsed.rejected
                }
                // a refused step may have left a text prompt open: close it, or every later step is refused and the user cannot even go offline
                if (refused != null) {
                    repeat(2) { if (parsed.promptOpen) parsed = Snapshot.parse(native.call("cancel", null)) }
                    latch(refused)
                }
                s.value = track(withLatch(parsed.copy(rejected = refused ?: parsed.rejected)))
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
    override fun addContact(name: String) = op("new_contact", text(name))
    override fun startOffer() = op("cmd", text("T"))
    override fun joinWithLink(link: String, code: CharArray) = op("cmd", text("J"), "submit" to text(link.trim()), "secret" to code, "enter" to null)
    override fun cancelPairing() = op("cmd", text("x"))
    override fun answerInPerson(inPerson: Boolean) = op("in_person", text(if (inPerson) "1" else "0"))
    override fun startVerify(contactId: Int) = op("select", text(contactId.toString()), "cmd" to text("v"))
    override fun confirmVerify(matches: Boolean) = op("verify", text(if (matches) "1" else "0"))
    override fun acknowledgeAlert() = op("ack_alert")
    override fun setPersist(persist: Persist) = op("persist", text(persist.name.lowercase()))

    /** Stop polling (tests, process end). The core itself ends with the process. */
    fun close() { closed = true; scope.cancel(); thread.shutdown() }
}
