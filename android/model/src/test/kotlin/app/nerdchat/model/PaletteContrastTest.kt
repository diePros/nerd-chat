package app.nerdchat.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PaletteContrastTest {
    private fun check(p: Palette, mode: String, s: Scheme): List<String> {
        val bad = mutableListOf<String>()
        fun need(name: String, fg: Long, bg: Long, min: Double) {
            val r = Contrast.ratio(fg, bg)
            if (r < min) bad += "${p.id}/$mode $name %.2f < $min".format(r)
        }
        // text pairs: WCAG AA 4.5
        need("onPrimary/primary", s.onPrimary, s.primary, 4.5)
        need("onPrimaryContainer/primaryContainer", s.onPrimaryContainer, s.primaryContainer, 4.5)
        need("onBackground/background", s.onBackground, s.background, 4.5)
        need("onSurface/surface", s.onSurface, s.surface, 4.5)
        need("muted/background", s.onSurfaceMuted, s.background, 4.5)
        need("muted/surface", s.onSurfaceMuted, s.surface, 4.5)
        need("onBubbleOut/bubbleOut", s.onBubbleOut, s.bubbleOut, 4.5)
        need("onBubbleIn/bubbleIn", s.onBubbleIn, s.bubbleIn, 4.5)
        need("onWarning/warning", s.onWarningContainer, s.warningContainer, 4.5)
        need("danger/background (text)", s.danger, s.background, 4.5)
        need("muted/chatBackground", s.onSurfaceMuted, s.chatBackground, 4.5)
        // controls and icons: 3
        need("primary/background", s.primary, s.background, 3.0)
        need("verified/background", s.verified, s.background, 3.0)
        need("delivered/bubbleOut", s.delivered, s.bubbleOut, 3.0)
        s.avatars.forEachIndexed { i, a -> need("avatar$i/white initials", 0xFFFFFFFF, a, 4.5) }
        // bubbles must stand out from the conversation background
        need("bubbleIn vs chatBackground", s.bubbleIn, s.chatBackground, 1.08)
        need("bubbleOut vs chatBackground", s.bubbleOut, s.chatBackground, 1.08)
        return bad
    }

    @Test fun everyPaletteMeetsContrastInBothModes() {
        val bad = Palettes.all.flatMap { check(it, "light", it.light) + check(it, "dark", it.dark) }
        assertTrue(bad.isEmpty(), "contrast failures:\n" + bad.joinToString("\n"))
    }

    @Test fun idsAreUniqueAndLookupFallsBackToTheDefault() {
        assertEquals(Palettes.all.size, Palettes.all.map { it.id }.toSet().size)
        assertEquals(Palettes.DEFAULT, Palettes.byId("no-such-palette"))
        assertEquals(Palettes.DEFAULT, Palettes.byId(null))
        Palettes.all.forEach { assertEquals(it, Palettes.byId(it.id)) }
    }

    @Test fun contrastMatchesKnownValues() {
        assertEquals(21.0, Contrast.ratio(0xFF000000, 0xFFFFFFFF), 0.01)
        assertEquals(1.0, Contrast.ratio(0xFF777777, 0xFF777777), 0.001)
    }
}
