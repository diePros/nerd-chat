package app.nerdchat.model

import kotlin.test.*

class SnapshotTest {
    private fun snap(body: String) = """{"v":1,"screen":"main","prompt":null,"status":"ok","error":false,"rejected":null,"pw_chars":0,"confirm_chars":0,"code_chars":0,"online":"offline","online_pct":0,"online_error":null,"sel":0,"pane":"details","mode":"normal","contacts":[],"chat":null,"detail":null,"verify_number":null,"tor_offer":null,"pairing_waiting":false,"alerts":[]$body}"""

    @Test fun screensMapToStages() {
        for ((screen, stage) in mapOf("unlock" to Stage.Unlock, "create_pw" to Stage.CreatePassword, "create_confirm" to Stage.ConfirmPassword,
            "working" to Stage.Working, "main" to Stage.Ready, "prompt" to Stage.Ready, "verify" to Stage.Ready, "wiped" to Stage.Wiped, "error" to Stage.Error)) {
            assertEquals(stage, Snapshot.parse(snap("").replace("\"screen\":\"main\"", "\"screen\":\"$screen\"")).stage, screen)
        }
    }

    @Test fun contactsChatLinesAndDeliveryMapToTheModel() {
        val s = Snapshot.parse(snap("").replace("\"contacts\":[]", """"contacts":[{"name":"Mira","trust":"verified","paired":true,"connected":true,"unread":2},{"name":"Li","trust":"unverified","paired":false,"connected":false,"unread":0}]""")
            .replace("\"online\":\"offline\"", "\"online\":\"online\"")
            .replace("\"chat\":null", """"chat":{"name":"Mira","trust":"verified","connected":true,"lines":[{"mine":false,"text":"hi","queued":false,"unsent":false,"unconfirmed":false,"saved":false},{"mine":true,"text":"a","queued":true,"unsent":false,"unconfirmed":false,"saved":false},{"mine":true,"text":"b","queued":false,"unsent":false,"unconfirmed":true,"saved":false},{"mine":true,"text":"c","queued":false,"unsent":true,"unconfirmed":false,"saved":false},{"mine":true,"text":"d","queued":false,"unsent":false,"unconfirmed":false,"saved":false}]}""")
            .replace("\"detail\":null", """"detail":{"name":"Mira","trust":"verified","safety":"48213 07791 36502","connection":"connected","we_host_now":true,"contact_can_host":true,"rotation":null}"""))
        assertTrue(s.online); assertEquals(TorState.Ready, s.tor)
        val (mira, li) = s.chats
        assertEquals(Trust.Verified, mira.contact.trust); assertEquals(Link.Connected, mira.contact.link); assertEquals(2, mira.unread)
        assertEquals(listOf("48213", "07791", "36502"), mira.contact.safetyNumber); assertTrue(mira.contact.weHost)
        assertFalse(li.contact.paired); assertEquals(Link.Offline, li.contact.link); assertTrue(li.contact.safetyNumber.isEmpty())
        val lines = s.messages[0]!!
        assertEquals(listOf(null, Delivery.Queued, Delivery.Unconfirmed, Delivery.Refused, Delivery.Delivered), lines.map { it.delivery })
        assertEquals(listOf(false, true, true, true, true), lines.map { it.fromMe })
        assertNull(s.messages[1], "only the open chat has lines")
    }

    @Test fun torOfferOnlineStatesAndAlertsMap() {
        val s = Snapshot.parse(snap("").replace("\"tor_offer\":null", """"tor_offer":{"link":"nerdchat:pair/x","code":"1234567890","expires_in":299,"for":"Sam"}""")
            .replace("\"online\":\"offline\",\"online_pct\":0", "\"online\":\"starting\",\"online_pct\":40").replace("\"alerts\":[]", """"alerts":[{"text":"careful","count":2}]""").replace("\"pairing_waiting\":false", "\"pairing_waiting\":true"))
        assertEquals(TorOffer("nerdchat:pair/x", "1234567890", 299, "Sam"), s.torOffer)
        assertEquals(TorState.Bootstrapping(40), s.tor); assertTrue(s.online); assertTrue(s.pairingWaiting); assertEquals(listOf("careful"), s.alerts)
        assertEquals(TorState.Failed("no tor"), Snapshot.parse(snap("").replace("\"online\":\"offline\"", "\"online\":\"failed\"").replace("\"online_error\":null", "\"online_error\":\"no tor\"")).tor)
    }

    @Test fun anUnknownVersionOrGarbageIsAnErrorStateNotACrash() {
        for (bad in listOf(snap("").replace("\"v\":1", "\"v\":2"), "not json", "{}", "[]")) {
            val s = Snapshot.parse(bad)
            assertEquals(Stage.Error, s.stage, bad); assertTrue(s.statusIsError)
        }
    }
}
