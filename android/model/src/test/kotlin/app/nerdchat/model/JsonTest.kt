package app.nerdchat.model

import kotlin.test.*

class JsonTest {
    @Test fun parsesNestedValues() {
        @Suppress("UNCHECKED_CAST")
        val m = Json.parse("""{"a":1,"b":true,"c":null,"d":[{"x":"y"},{},"z"],"e":{"n":null,"s":"t"},"f":-2.5e1}""") as Map<String, Any?>
        assertEquals(1.0, m["a"]); assertEquals(true, m["b"]); assertNull(m["c"]); assertEquals(-25.0, m["f"])
        assertEquals(listOf(mapOf("x" to "y"), emptyMap<String, Any?>(), "z"), m["d"])
    }

    @Test fun parsesWhatTheRustWriterProduces() {
        // exactly the escaping test string of crates/android/src/json.rs
        val rust = "{\"t\":\"q\\\"b\\\\n\\nr\\rt\\tc\\u0001d\\u007fe\\u2028ü😀\"}"
        @Suppress("UNCHECKED_CAST")
        assertEquals("q\"b\\n\nr\rt\tc\u0001d\u007fe\u2028ü😀", (Json.parse(rust) as Map<String, Any?>)["t"])
    }

    @Test fun rejectsBrokenInputInsteadOfGuessing() {
        for (bad in listOf("", "{", "{\"a\":}", "[1,]", "{\"a\":1} x", "\"unterminated", "\"bad \\q escape\"", "{\"a\" 1}", "nul", "\"raw\ncontrol\"", "\"\\u12\"")) {
            assertFailsWith<IllegalArgumentException>(bad) { Json.parse(bad) }
        }
    }
}
