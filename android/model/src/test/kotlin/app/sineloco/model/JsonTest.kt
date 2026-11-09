package app.sineloco.model

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

    @Test fun veryDeepNestingIsRefusedInsteadOfOverflowingTheStack() {
        assertFailsWith<IllegalArgumentException> { Json.parse("[".repeat(100) + "]".repeat(100)) }
        assertEquals(listOf(listOf(listOf<Any?>())), Json.parse("[[[]]]"))
        assertFailsWith<IllegalArgumentException> { Json.parse("{\"a\":".repeat(100) + "1" + "}".repeat(100)) }
    }

    @Test fun aUnicodeEscapeNeedsExactlyFourHexDigits() {
        assertEquals("A", Json.parse("\"\\u0041\""))
        for (bad in listOf("\"\\u+041\"", "\"\\u-041\"", "\"\\u 041\"", "\"\\u00zz\"")) assertFailsWith<IllegalArgumentException>(bad) { Json.parse(bad) }
    }

    @Test fun rejectsBrokenInputInsteadOfGuessing() {
        for (bad in listOf("", "{", "{\"a\":}", "[1,]", "{\"a\":1} x", "\"unterminated", "\"bad \\q escape\"", "{\"a\" 1}", "nul", "\"raw\ncontrol\"", "\"\\u12\"")) {
            assertFailsWith<IllegalArgumentException>(bad) { Json.parse(bad) }
        }
    }
}
