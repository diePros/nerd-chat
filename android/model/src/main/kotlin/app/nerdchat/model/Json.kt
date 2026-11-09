package app.nerdchat.model

/**
 * A minimal JSON reader for the core's snapshot (no dependency, so it runs on the JVM and on Android alike). Values become
 * `Map<String, Any?>`, `List<Any?>`, `String`, `Double`, `Boolean` or `null`. Strict: trailing garbage, bad escapes and unterminated
 * input throw [IllegalArgumentException] instead of returning something half-read.
 */
object Json {
    fun parse(text: String): Any? {
        val p = Parser(text)
        val v = p.value()
        p.ws()
        require(p.i == text.length) { "trailing data at ${p.i}" }
        return v
    }

    private class Parser(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && s[i] in " \t\r\n") i++ }
        private fun peek(): Char { require(i < s.length) { "unexpected end" }; return s[i] }
        private fun expect(c: Char) { require(peek() == c) { "expected '$c' at $i" }; i++ }
        fun value(): Any? {
            ws()
            return when (val c = peek()) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c.isDigit()) num() else throw IllegalArgumentException("unexpected '$c' at $i")
            }
        }
        private fun lit(word: String, v: Any?): Any? { require(s.startsWith(word, i)) { "bad literal at $i" }; i += word.length; return v }
        private fun num(): Double {
            val st = i
            if (peek() == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            return s.substring(st, i).toDoubleOrNull() ?: throw IllegalArgumentException("bad number at $st")
        }
        private fun obj(): Map<String, Any?> {
            expect('{'); val m = LinkedHashMap<String, Any?>(); ws()
            if (peek() == '}') { i++; return m }
            while (true) {
                ws(); val k = str(); ws(); expect(':'); m[k] = value(); ws()
                when (peek()) { ',' -> i++; '}' -> { i++; return m }; else -> throw IllegalArgumentException("expected ',' or '}' at $i") }
            }
        }
        private fun arr(): List<Any?> {
            expect('['); val l = ArrayList<Any?>(); ws()
            if (peek() == ']') { i++; return l }
            while (true) {
                l += value(); ws()
                when (peek()) { ',' -> i++; ']' -> { i++; return l }; else -> throw IllegalArgumentException("expected ',' or ']' at $i") }
            }
        }
        private fun str(): String {
            expect('"'); val b = StringBuilder()
            while (true) {
                val c = peek(); i++
                when {
                    c == '"' -> return b.toString()
                    c == '\\' -> {
                        when (val e = peek()) {
                            '"', '\\', '/' -> b.append(e)
                            'n' -> b.append('\n'); 'r' -> b.append('\r'); 't' -> b.append('\t'); 'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                            'u' -> { require(i + 5 <= s.length) { "bad \\u escape" }; b.append(s.substring(i + 1, i + 5).toIntOrNull(16)?.toChar() ?: throw IllegalArgumentException("bad \\u escape at $i")); i += 4 }
                            else -> throw IllegalArgumentException("bad escape '\\$e' at $i")
                        }
                        i++
                    }
                    c < ' ' -> throw IllegalArgumentException("raw control character in string at ${i - 1}")
                    else -> b.append(c)
                }
            }
        }
    }
}
