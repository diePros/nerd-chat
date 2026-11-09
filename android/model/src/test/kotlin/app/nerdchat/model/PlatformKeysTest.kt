package app.nerdchat.model

import kotlin.test.*

class PlatformKeysTest {
    private val key = ByteArray(32) { it.toByte() }

    @Test fun wrapThenUnwrapGivesTheKeyBack() {
        val k = SoftwareKeys()
        val blob = assertNotNull(k.wrap(5, key))
        assertContentEquals(key, k.unwrap(5, blob))
        assertNotEquals(blob.toList(), k.wrap(5, key)!!.toList(), "a fresh IV every time")
    }

    @Test fun anErasedEpochCannotBeOpenedAgainAndOtherEpochsStillCan() {
        val k = SoftwareKeys()
        val a = k.wrap(1, key)!!; val b = k.wrap(2, key)!!
        k.erase(1)
        assertNull(k.unwrap(1, a), "erased")
        assertContentEquals(key, k.unwrap(2, b))
        assertEquals(listOf(1), k.erased)
    }

    @Test fun aBlobIsBoundToItsEpochAndToItself() {
        val k = SoftwareKeys()
        val blob = k.wrap(3, key)!!
        k.wrap(4, key) // epoch 4 has a key now
        assertNull(k.unwrap(4, blob), "a blob of epoch 3 does not open under epoch 4")
        assertNull(k.unwrap(3, blob.copyOf().also { it[20] = (it[20] + 1).toByte() }), "tampered")
        assertNull(k.unwrap(3, ByteArray(5)), "too short")
        assertNull(k.unwrap(3, blob.copyOf().also { it[0] = 2 }), "unknown version")
    }

    /** The Rust side calls these by name and descriptor (`crates/android/src/keys.rs`): renaming or retyping them breaks the phone and nothing else notices. */
    @Test fun theNamesAndDescriptorsTheCoreCallsAreFixed() {
        val m = PlatformKeys::class.java.methods.associateBy { it.name }
        assertEquals(setOf("wrap", "unwrap", "erase"), m.keys)
        assertEquals(listOf(Int::class.javaPrimitiveType, ByteArray::class.java), m["wrap"]!!.parameterTypes.toList()); assertEquals(ByteArray::class.java, m["wrap"]!!.returnType)
        assertEquals(listOf(Int::class.javaPrimitiveType, ByteArray::class.java), m["unwrap"]!!.parameterTypes.toList()); assertEquals(ByteArray::class.java, m["unwrap"]!!.returnType)
        assertEquals(listOf(Int::class.javaPrimitiveType), m["erase"]!!.parameterTypes.toList()); assertEquals(Void.TYPE, m["erase"]!!.returnType)
    }
}
