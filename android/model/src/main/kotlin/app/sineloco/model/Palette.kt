package app.sineloco.model

/**
 * The colour tokens of one palette in one mode (light or dark). Colours are 0xAARRGGBB longs so this file has no UI dependency.
 * To change the look of the app edit [Palettes] (one block per palette); `PaletteContrastTest` fails if a text/background pair
 * drops below WCAG AA (4.5:1 text, 3:1 large text and controls).
 */
data class Scheme(
    val primary: Long, val onPrimary: Long,
    val primaryContainer: Long, val onPrimaryContainer: Long,
    val background: Long, val onBackground: Long,
    val surface: Long, val onSurface: Long, val onSurfaceMuted: Long,
    val outline: Long,
    /** the conversation background and the faint onion-ring pattern drawn on it */
    val chatBackground: Long, val chatPattern: Long,
    val bubbleOut: Long, val onBubbleOut: Long,
    val bubbleIn: Long, val onBubbleIn: Long,
    /** tint of the "their app has it" check marks (never blue: this is NOT a read receipt) */
    val delivered: Long,
    val verified: Long,
    val warningContainer: Long, val onWarningContainer: Long,
    val danger: Long,
    /** contact avatar backgrounds (white initials), picked by a hash of the name */
    val avatars: List<Long>,
)

data class Palette(val id: String, val name: String, val tagline: String, val light: Scheme, val dark: Scheme) {
    fun scheme(dark: Boolean) = if (dark) this.dark else this.light
}
