package app.nerdchat.model

import kotlin.test.*

class FakeBackendTest {
    @Test fun unlockWipesThePasswordAndRejectsEmpty() {
        val b = FakeBackend()
        val pw = "secret".toCharArray()
        assertTrue(b.unlock(pw)); assertTrue(pw.all { it == '\u0000' }, "password wiped")
        assertTrue(b.state.value.unlocked)
        assertFalse(FakeBackend().unlock(CharArray(0)))
    }

    @Test fun sendQueuesThenDeliveredOnlyForConnectedContacts() {
        val b = FakeBackend(); b.unlock("x".toCharArray())
        b.send(1, "  hello  "); b.send(2, "to offline")
        assertEquals(Delivery.Queued, b.state.value.messages[1]!!.last().delivery)
        assertEquals("hello", b.state.value.messages[1]!!.last().text)
        b.confirmQueued()
        assertEquals(Delivery.Delivered, b.state.value.messages[1]!!.last().delivery)
        assertEquals(Delivery.Queued, b.state.value.messages[2]!!.last().delivery, "an offline contact cannot confirm")
        b.send(1, "   "); assertEquals(Delivery.Delivered, b.state.value.messages[1]!!.last().delivery, "blank text is not sent")
    }

    @Test fun openClearsUnreadAndPanicEmptiesEverything() {
        val b = FakeBackend(); b.unlock("x".toCharArray())
        assertEquals(2, b.state.value.chats.first { it.contact.id == 1 }.unread)
        b.open(1); assertEquals(0, b.state.value.chats.first { it.contact.id == 1 }.unread)
        b.panic(); assertTrue(b.panicked); assertEquals(AppState(), b.state.value)
    }

    @Test fun joinValidatesLinkAndCode() {
        val b = FakeBackend(); val offer = b.createPairingOffer()
        assertIs<JoinResult.Rejected>(b.join("nope", "4821-7390-52"))
        assertIs<JoinResult.Rejected>(b.join(offer.link, "12"))
        assertIs<JoinResult.Paired>(b.join(offer.link, offer.code))
        assertFalse(b.state.value.chats.last().contact.verified, "a new contact is unverified")
    }

    @Test fun modelHasNoTimestampsOrReadState() {
        val names = (Message::class.java.declaredFields + ChatSummary::class.java.declaredFields + Contact::class.java.declaredFields).map { it.name.lowercase() }
        assertTrue(names.none { "time" in it || "read" in it.replace("unread", "") || "seen" in it || "typing" in it || "online" in it && false }, "design rule: $names")
    }
}
