package app.sineloco.model

/**
 * What a pairing QR code (or a `sineloco:` link opened from another app) carries. The QR is for an IN-PERSON exchange: it holds the link AND the code in one, so it must only ever be
 * shown to the person standing in front of you (the Tor link alone is useless without the code, which is why the text link and the code travel by different channels).
 *
 *  * `sineloco:pair/<56-character onion id>#<10 digits>`  pairing over Tor
 *  * `sineloco:lan/<ip>:<port>#<10 digits>`                pairing on the local network
 *
 * Parsing never acts on anything: the app only PRE-FILLS the form, and the user presses Pair.
 */
sealed interface PairLink {
    val code: String?
    data class Tor(val link: String, override val code: String?) : PairLink
    data class Lan(val addr: String, override val code: String?) : PairLink

    companion object {
        fun torQr(link: String, code: String) = "${link.trim()}#${code.filter { it.isDigit() }}"
        fun lanQr(addr: String, code: String) = "sineloco:lan/${addr.trim()}#${code.filter { it.isDigit() }}"

        fun parse(text: String?): PairLink? {
            val t = text?.trim() ?: return null
            if (t.length > 300) return null
            val hash = t.indexOf('#')
            val main = if (hash >= 0) t.substring(0, hash) else t
            val code = if (hash >= 0) t.substring(hash + 1).filter { it.isDigit() }.takeIf { it.length == 10 } else null
            val lower = main.lowercase()
            return when {
                lower.startsWith("sineloco:pair/") -> {
                    val id = main.substring("sineloco:pair/".length).lowercase().removeSuffix(".onion")
                    if (id.length == 56 && id.all { it in 'a'..'z' || it in '2'..'7' }) Tor("sineloco:pair/$id", code) else null
                }
                lower.startsWith("sineloco:lan/") -> {
                    val a = main.substring("sineloco:lan/".length)
                    val ok = a.count { it == ':' } == 1 && a.substringAfter(':').toIntOrNull()?.let { it in 1..65535 } == true &&
                        a.substringBefore(':').split('.').let { p -> p.size == 4 && p.all { x -> x.toIntOrNull()?.let { it in 0..255 } == true } }
                    if (ok) Lan(a, code) else null
                }
                else -> null
            }
        }
    }
}
