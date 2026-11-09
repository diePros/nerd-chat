package app.sineloco.model

/**
 * Turns the core's JSON snapshot (docs: `crates/android/src/snapshot.rs`, `"v": 1`) into [AppState]. A snapshot of another version or one that
 * does not parse becomes an [Stage.Error] state with the reason, never an exception and never a half-filled screen.
 */
object Snapshot {
    const val VERSION = 1

    @Suppress("UNCHECKED_CAST")
    fun parse(json: String): AppState = try {
        val m = Json.parse(json) as Map<String, Any?>
        val v = (m["v"] as? Double)?.toInt()
        if (v != VERSION) error("unsupported snapshot version $v (this app speaks $VERSION)")
        map(m)
    } catch (e: Exception) {
        AppState(stage = Stage.Error, status = "The core answered something this app cannot read: ${e.message}", statusIsError = true)
    }

    private fun Map<String, Any?>.str(k: String) = this[k] as? String
    private fun Map<String, Any?>.bool(k: String) = this[k] as? Boolean ?: false
    private fun Map<String, Any?>.int(k: String) = (this[k] as? Double)?.toInt() ?: 0
    @Suppress("UNCHECKED_CAST") private fun Map<String, Any?>.obj(k: String) = this[k] as? Map<String, Any?>
    @Suppress("UNCHECKED_CAST") private fun Map<String, Any?>.list(k: String) = (this[k] as? List<Any?>).orEmpty().filterIsInstance<Map<String, Any?>>()

    private fun trust(s: String?) = when (s) { "verified" -> Trust.Verified; "code" -> Trust.Code; else -> Trust.Unverified }

    @Suppress("UNCHECKED_CAST")
    private fun map(m: Map<String, Any?>): AppState {
        val stage = when (m.str("screen")) {
            "unlock" -> Stage.Unlock
            "create_pw" -> Stage.CreatePassword
            "create_confirm" -> Stage.ConfirmPassword
            "working" -> Stage.Working
            "wiped" -> Stage.Wiped
            "main", "prompt", "verify" -> Stage.Ready // the app draws its own screens for these
            // anything else (an error from the bridge, a screen added later, the core's privacy screen) must NOT show the main UI
            else -> Stage.Error
        }
        if (m.bool("privacy_locked")) return AppState(stage = Stage.Error, status = "The core is showing its privacy screen, which this app does not use.", statusIsError = true)
        val onlineKind = m.str("online")
        val tor = when (onlineKind) {
            "starting" -> TorState.Bootstrapping(m.int("online_pct"))
            "online" -> TorState.Ready
            "failed" -> TorState.Failed(m.str("online_error") ?: "failed")
            else -> TorState.Off
        }
        val online = onlineKind == "starting" || onlineKind == "online"
        val sel = m.int("sel")
        val detail = m.obj("detail")
        val chat = m.obj("chat")
        val contacts = m.list("contacts").mapIndexed { i, c ->
            val paired = c.bool("paired")
            val link = when { c.bool("connected") -> Link.Connected; paired && onlineKind == "online" -> Link.Connecting; else -> Link.Offline }
            val d = if (i == sel) detail else null
            val safety = d?.str("safety")?.trim()?.split(Regex("\\s+"))?.filter { it.isNotEmpty() }.orEmpty()
            ChatSummary(
                Contact(i, c.str("name") ?: "?", trust(c.str("trust")), paired, link, safety, "", d?.get("we_host_now") as? Boolean ?: false),
                preview = null, unread = c.int("unread"),
            )
        }
        val messages = if (chat != null && sel in contacts.indices) {
            mapOf(sel to (chat["lines"] as? List<Any?>).orEmpty().filterIsInstance<Map<String, Any?>>().mapIndexed { i, l ->
                val mine = l.bool("mine")
                val delivery = when {
                    !mine -> null
                    l.bool("unsent") -> Delivery.Refused
                    l.bool("queued") -> Delivery.Queued
                    l.bool("unconfirmed") -> Delivery.Unconfirmed
                    else -> Delivery.Delivered
                }
                Message(i.toLong(), mine, l.str("text") ?: "", delivery)
            })
        } else emptyMap()
        val offer = m.obj("tor_offer")?.let { TorOffer(it.str("link") ?: "", it.str("code") ?: "", it.int("expires_in"), it.str("for")) }
        return AppState(
            stage = stage, status = m.str("status") ?: "", statusIsError = m.bool("error"), pwChars = m.int("pw_chars"),
            tor = tor, online = online, chats = contacts, messages = messages, torOffer = offer,
            pairingWaiting = m.bool("pairing_waiting"), verifyNumber = m.str("verify_number"),
            alerts = m.list("alerts").mapNotNull { it.str("text") }, rejected = m.str("rejected"), persist = when (m.str("persist")) { "outbox" -> Persist.Outbox; "day" -> Persist.Day; "week" -> Persist.Week; else -> Persist.Off }, promptOpen = m.str("screen") == "prompt",
        )
    }
}
