package app.nerdchat.model

import kotlin.math.pow

/** WCAG 2.x contrast ratio between two 0xAARRGGBB colours (alpha ignored: palette colours are opaque). */
object Contrast {
    private fun lin(c: Int): Double { val s = c / 255.0; return if (s <= 0.03928) s / 12.92 else ((s + 0.055) / 1.055).pow(2.4) }
    fun luminance(argb: Long): Double {
        val r = ((argb shr 16) and 0xFF).toInt(); val g = ((argb shr 8) and 0xFF).toInt(); val b = (argb and 0xFF).toInt()
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }
    fun ratio(a: Long, b: Long): Double {
        val (x, y) = luminance(a) to luminance(b)
        return (maxOf(x, y) + 0.05) / (minOf(x, y) + 0.05)
    }
}
