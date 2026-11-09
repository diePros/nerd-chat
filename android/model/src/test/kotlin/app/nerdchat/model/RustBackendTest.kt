package app.nerdchat.model

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.*

/** [RustBackend] against a scripted [Native]: which operations does each user action send, in which order, with which text, and are secrets wiped? */
class RustBackendTest {
    private class Script : Native {
        val calls = CopyOnWriteArrayList<Pair<String, String?>>()
        var lastArrays = CopyOnWriteArrayList<CharArray>()
        val answer = """{"v":1,"screen":"main","status":"","error":false,"online":"offline","contacts":[],"chat":null,"detail":null,"alerts":[]}"""
        override fun init(vaultDir: String, lowMem: Boolean, torPath: String?, keepOutboxDefault: Boolean): String = answer.replace("\"main\"", "\"unlock\"")
        override fun call(op: String, arg: CharArray?): String { if (op != "snapshot") { calls += op to arg?.concatToString(); arg?.let { lastArrays += it } }; return answer }
    }

    private fun backend(n: Native) = RustBackend(n, "/v", false, null, true, pollMillis = 5, pollMillisBusy = 5)
    private fun awaitCalls(s: Script, n: Int) = runBlocking { repeat(400) { if (s.calls.size < n) delay(5) }; assertTrue(s.calls.size >= n, "expected $n calls, got ${s.calls}") }

    @Test fun initialStateComesFromTheFirstSnapshot() {
        val b = backend(Script()); assertEquals(Stage.Unlock, b.state.value.stage); b.close()
    }

    @Test fun eachActionSendsTheRightOperationsInOrder() {
        val s = Script(); val b = backend(s)
        b.submitPassword("pw".toCharArray()); b.open(3); b.closeChat(); b.send(3, "hello"); b.addContact("Sam"); b.startOffer()
        b.joinWithLink("  nerdchat:pair/abc ", "4821739052".toCharArray()); b.cancelPairing(); b.answerInPerson(true); b.answerInPerson(false)
        b.startVerify(2); b.confirmVerify(true); b.setOnline(true); b.setOnline(false); b.acknowledgeAlert(); b.setKeepOutbox(true); b.setKeepOutbox(false); b.panic(); b.purge()
        awaitCalls(s, 26)
        assertEquals(listOf(
            "secret" to "pw", "enter" to null, "select" to "3", "open_chat" to null, "back" to null, "send" to "hello",
            "cmd" to "n", "submit" to "Sam", "cmd" to "T", "cmd" to "J", "submit" to "nerdchat:pair/abc", "secret" to "4821739052", "enter" to null,
            "cmd" to "x", "in_person" to "1", "in_person" to "0", "select" to "2", "cmd" to "v", "verify" to "1",
            "online" to "1", "online" to "0", "ack_alert" to null, "keep_outbox" to "1", "keep_outbox" to "0", "panic" to null, "purge" to null,
        ), s.calls.take(26).map { it.first to it.second })
        b.close()
    }

    @Test fun secretArraysAreWipedAfterTheCall() {
        val s = Script(); val b = backend(s)
        val pw = "hunter2-hunter2".toCharArray(); val code = "4821739052".toCharArray()
        b.submitPassword(pw); b.joinWithLink("nerdchat:pair/x", code)
        awaitCalls(s, 6)
        runBlocking { delay(50) }
        assertTrue(pw.all { it == '\u0000' }, "password array wiped"); assertTrue(code.all { it == '\u0000' }, "code array wiped")
        assertTrue(s.lastArrays.all { a -> a.all { it == '\u0000' } }, "every array handed to the core is wiped afterwards")
        b.close()
    }

    @Test fun theTickerKeepsPollingAndPublishingState() {
        val s = Script(); val b = backend(s)
        runBlocking { delay(100) }
        assertEquals(Stage.Ready, b.state.value.stage, "the poll replaced the initial state")
        b.close()
    }
}
