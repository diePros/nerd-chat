package app.nerdchat.model

import kotlin.test.*

class FakeBackendTest {
    private fun pw(s: String) = s.toCharArray()

    @Test fun unlockWipesThePasswordAndRejectsEmpty() {
        val b = FakeBackend()
        val p = pw("secret")
        b.submitPassword(p); assertTrue(p.all { it == '\u0000' }, "password wiped")
        assertEquals(Stage.Ready, b.state.value.stage)
        val e = FakeBackend(); e.submitPassword(CharArray(0))
        assertEquals(Stage.Unlock, e.state.value.stage); assertTrue(e.state.value.statusIsError)
    }

    @Test fun firstRunFollowsTheCoreRulesMinimumLengthThenConfirm() {
        val b = FakeBackend(hasVault = false)
        assertEquals(Stage.CreatePassword, b.state.value.stage)
        b.submitPassword(pw("short")); assertEquals(Stage.CreatePassword, b.state.value.stage); assertTrue(b.state.value.status.contains("Too short"))
        b.submitPassword(pw("a long enough passphrase")); assertEquals(Stage.ConfirmPassword, b.state.value.stage)
        b.submitPassword(pw("something else entirely")); assertEquals(Stage.CreatePassword, b.state.value.stage); assertTrue(b.state.value.status.contains("did not match"))
        b.submitPassword(pw("a long enough passphrase")); b.submitPassword(pw("a long enough passphrase"))
        assertEquals(Stage.Ready, b.state.value.stage)
    }

    @Test fun sendQueuesThenDeliveredOnlyForConnectedContacts() {
        val b = FakeBackend(); b.submitPassword(pw("x"))
        b.send(0, "  hello  "); b.send(2, "to offline")
        assertEquals(Delivery.Queued, b.state.value.messages[0]!!.last().delivery)
        assertEquals("hello", b.state.value.messages[0]!!.last().text)
        b.confirmQueued()
        assertEquals(Delivery.Delivered, b.state.value.messages[0]!!.last().delivery)
        assertEquals(Delivery.Queued, b.state.value.messages[2]!!.last().delivery, "an offline contact cannot confirm")
        b.send(0, "   "); assertEquals(Delivery.Delivered, b.state.value.messages[0]!!.last().delivery, "blank text is not sent")
    }

    @Test fun openClearsUnreadAndPanicEmptiesEverything() {
        val b = FakeBackend(); b.submitPassword(pw("x"))
        assertEquals(2, b.state.value.chats.first { it.contact.id == 0 }.unread)
        b.open(0); assertEquals(0, b.state.value.chats.first { it.contact.id == 0 }.unread)
        b.panic(); assertTrue(b.panicked); assertEquals(AppState(stage = Stage.Wiped), b.state.value)
    }

    @Test fun pairingAddsAnUnverifiedContactAndAsksTheInPersonQuestion() {
        val b = FakeBackend(); b.submitPassword(pw("x"))
        b.joinWithLink("nope", pw("4821739052")); assertTrue(b.state.value.statusIsError); assertFalse(b.state.value.pairingWaiting)
        b.joinWithLink("nerdchat:pair/" + "a".repeat(56), pw("12")); assertTrue(b.state.value.statusIsError)
        b.addContact("Sam")
        b.joinWithLink("nerdchat:pair/" + "a".repeat(56), pw("4821-7390-52")); assertTrue(b.state.value.pairingWaiting)
        b.answerInPerson(false)
        val sam = b.state.value.chats.last().contact
        assertEquals("Sam", sam.name); assertTrue(sam.paired); assertEquals(Trust.Unverified, sam.trust); assertFalse(b.state.value.pairingWaiting)
    }

    @Test fun verifyingNeedsTheComparisonAndOnlyAMatchUpgradesTrust() {
        val b = FakeBackend(); b.submitPassword(pw("x"))
        b.startVerify(1); assertNotNull(b.state.value.verifyNumber)
        b.confirmVerify(false); assertNull(b.state.value.verifyNumber); assertEquals(Trust.Unverified, b.state.value.chats[1].contact.trust)
        b.startVerify(1); b.confirmVerify(true); assertEquals(Trust.Verified, b.state.value.chats[1].contact.trust)
    }

    @Test fun offerAppearsForTheNewContact() {
        val b = FakeBackend(); b.submitPassword(pw("x"))
        b.addContact("Sam"); b.startOffer()
        val o = b.state.value.torOffer!!
        assertEquals("Sam", o.forContact); assertTrue(o.link.startsWith("nerdchat:pair/")); assertEquals(12, o.code.length)
    }

    @Test fun modelHasNoTimestampsOrReadState() {
        val fields = listOf(Message::class, ChatSummary::class, Contact::class, AppState::class, TorOffer::class).flatMap { it.java.declaredFields.toList() }.map { it.name.lowercase() }
        assertTrue(fields.none { "time" in it || "seen" in it || "typing" in it || ("read" in it && "unread" !in it) }, "design rule: $fields")
    }
}
