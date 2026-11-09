package app.nerdchat.model

/**
 * The selectable palettes. EASY TO ADJUST: change a hex value, run `gradle :model:test`; add a palette by adding a block and listing it in [all].
 * [DEFAULT] is what a fresh install uses.
 */
object Palettes {
    val Fern = Palette(
        id = "fern", name = "Fern", tagline = "Familiar green, warm paper background",
        light = Scheme(
            primary = 0xFF1F7A5C, onPrimary = 0xFFFFFFFF, primaryContainer = 0xFFD3EFE2, onPrimaryContainer = 0xFF08281D,
            background = 0xFFFFFFFF, onBackground = 0xFF111B21, surface = 0xFFF4F6F5, onSurface = 0xFF111B21, onSurfaceMuted = 0xFF56636B,
            outline = 0xFFD3DAD7, chatBackground = 0xFFECE6DA, chatPattern = 0xFFE0D8C8,
            bubbleOut = 0xFFBFE6CF, onBubbleOut = 0xFF0B2A1F, bubbleIn = 0xFFFFFFFF, onBubbleIn = 0xFF111B21,
            delivered = 0xFF1F7A5C, verified = 0xFF1F7A5C, warningContainer = 0xFFFFF0C2, onWarningContainer = 0xFF4A3500, danger = 0xFFC62828,
            avatars = listOf(0xFF1F7A5C, 0xFF3D6FA5, 0xFF8A5A9E, 0xFF9E5512, 0xFF4F7F2F, 0xFFA23B4C),
        ),
        dark = Scheme(
            primary = 0xFF4CC38F, onPrimary = 0xFF04281A, primaryContainer = 0xFF124A36, onPrimaryContainer = 0xFFC9F2DF,
            background = 0xFF0B1411, onBackground = 0xFFE6EEEA, surface = 0xFF121C18, onSurface = 0xFFE6EEEA, onSurfaceMuted = 0xFF9DADA6,
            outline = 0xFF2A3833, chatBackground = 0xFF0E1A16, chatPattern = 0xFF15251F,
            bubbleOut = 0xFF13503B, onBubbleOut = 0xFFE6F6EE, bubbleIn = 0xFF1B2823, onBubbleIn = 0xFFE6EEEA,
            delivered = 0xFF4CC38F, verified = 0xFF4CC38F, warningContainer = 0xFF4A3B10, onWarningContainer = 0xFFFFE9A8, danger = 0xFFFF8A80,
            avatars = listOf(0xFF1F7A5C, 0xFF3D6FA5, 0xFF8A5A9E, 0xFF9E5512, 0xFF4F7F2F, 0xFFA23B4C),
        ),
    )

    val Onion = Palette(
        id = "onion", name = "Onion", tagline = "Tor purple, a nod to the layers",
        light = Scheme(
            primary = 0xFF6B3FA0, onPrimary = 0xFFFFFFFF, primaryContainer = 0xFFE9DDF7, onPrimaryContainer = 0xFF2A1346,
            background = 0xFFFFFFFF, onBackground = 0xFF1A1523, surface = 0xFFF6F3FA, onSurface = 0xFF1A1523, onSurfaceMuted = 0xFF5F5870,
            outline = 0xFFDAD3E4, chatBackground = 0xFFEFEAF5, chatPattern = 0xFFE3DBEE,
            bubbleOut = 0xFFE3D4F5, onBubbleOut = 0xFF2A1346, bubbleIn = 0xFFFFFFFF, onBubbleIn = 0xFF1A1523,
            delivered = 0xFF6B3FA0, verified = 0xFF6B3FA0, warningContainer = 0xFFFFF0C2, onWarningContainer = 0xFF4A3500, danger = 0xFFC62828,
            avatars = listOf(0xFF6B3FA0, 0xFF2F6F8F, 0xFFA23B72, 0xFF7A5C1F, 0xFF3F7A4F, 0xFF8F3F3F),
        ),
        dark = Scheme(
            primary = 0xFFB792F0, onPrimary = 0xFF2A1346, primaryContainer = 0xFF47297A, onPrimaryContainer = 0xFFEBDDFF,
            background = 0xFF120E1A, onBackground = 0xFFEDE8F5, surface = 0xFF1A1524, onSurface = 0xFFEDE8F5, onSurfaceMuted = 0xFFA79FB8,
            outline = 0xFF352E45, chatBackground = 0xFF15101E, chatPattern = 0xFF1D1628,
            bubbleOut = 0xFF47297A, onBubbleOut = 0xFFF1E8FF, bubbleIn = 0xFF241D31, onBubbleIn = 0xFFEDE8F5,
            delivered = 0xFFB792F0, verified = 0xFFB792F0, warningContainer = 0xFF4A3B10, onWarningContainer = 0xFFFFE9A8, danger = 0xFFFF8A80,
            avatars = listOf(0xFF6B3FA0, 0xFF2F6F8F, 0xFFA23B72, 0xFF7A5C1F, 0xFF3F7A4F, 0xFF8F3F3F),
        ),
    )

    val Midnight = Palette(
        id = "midnight", name = "Midnight", tagline = "Deep blue with a cool cyan accent",
        light = Scheme(
            primary = 0xFF1565C0, onPrimary = 0xFFFFFFFF, primaryContainer = 0xFFD6E6FA, onPrimaryContainer = 0xFF08254A,
            background = 0xFFFFFFFF, onBackground = 0xFF0F1A28, surface = 0xFFF2F6FA, onSurface = 0xFF0F1A28, onSurfaceMuted = 0xFF52627A,
            outline = 0xFFD0D9E4, chatBackground = 0xFFE6EDF5, chatPattern = 0xFFD8E2EE,
            bubbleOut = 0xFFD2E4FA, onBubbleOut = 0xFF08254A, bubbleIn = 0xFFFFFFFF, onBubbleIn = 0xFF0F1A28,
            delivered = 0xFF1565C0, verified = 0xFF0B7A8F, warningContainer = 0xFFFFF0C2, onWarningContainer = 0xFF4A3500, danger = 0xFFC62828,
            avatars = listOf(0xFF1565C0, 0xFF0B7A8F, 0xFF6B4BA0, 0xFF9E5512, 0xFF3F7A4F, 0xFFA23B4C),
        ),
        dark = Scheme(
            primary = 0xFF6FB5FF, onPrimary = 0xFF04213F, primaryContainer = 0xFF123F73, onPrimaryContainer = 0xFFD6E8FF,
            background = 0xFF0A0F18, onBackground = 0xFFE6ECF5, surface = 0xFF111826, onSurface = 0xFFE6ECF5, onSurfaceMuted = 0xFF9BA9BF,
            outline = 0xFF263248, chatBackground = 0xFF0C121D, chatPattern = 0xFF131B2B,
            bubbleOut = 0xFF123F73, onBubbleOut = 0xFFE6F0FF, bubbleIn = 0xFF1A2335, onBubbleIn = 0xFFE6ECF5,
            delivered = 0xFF6FB5FF, verified = 0xFF5CD0E6, warningContainer = 0xFF4A3B10, onWarningContainer = 0xFFFFE9A8, danger = 0xFFFF8A80,
            avatars = listOf(0xFF1565C0, 0xFF0B7A8F, 0xFF6B4BA0, 0xFF9E5512, 0xFF3F7A4F, 0xFFA23B4C),
        ),
    )

    val Graphite = Palette(
        id = "graphite", name = "Graphite", tagline = "Neutral greys, amber highlights, least conspicuous",
        light = Scheme(
            primary = 0xFF37474F, onPrimary = 0xFFFFFFFF, primaryContainer = 0xFFE2E7EA, onPrimaryContainer = 0xFF141C20,
            background = 0xFFFFFFFF, onBackground = 0xFF1B1F22, surface = 0xFFF3F4F5, onSurface = 0xFF1B1F22, onSurfaceMuted = 0xFF5A6368,
            outline = 0xFFD6D9DB, chatBackground = 0xFFE9EAEB, chatPattern = 0xFFDDDFE0,
            bubbleOut = 0xFFD3DBDF, onBubbleOut = 0xFF141C20, bubbleIn = 0xFFFFFFFF, onBubbleIn = 0xFF1B1F22,
            delivered = 0xFF8A5A00, verified = 0xFF8A5A00, warningContainer = 0xFFFFF0C2, onWarningContainer = 0xFF4A3500, danger = 0xFFC62828,
            avatars = listOf(0xFF546E7A, 0xFF8A5A00, 0xFF6D4C41, 0xFF455A64, 0xFF5D4A7A, 0xFF7A3F3F),
        ),
        dark = Scheme(
            primary = 0xFFFFB74D, onPrimary = 0xFF3A2600, primaryContainer = 0xFF4A3410, onPrimaryContainer = 0xFFFFE3B8,
            background = 0xFF0F1113, onBackground = 0xFFE8EAEB, surface = 0xFF181B1D, onSurface = 0xFFE8EAEB, onSurfaceMuted = 0xFFA0A6AA,
            outline = 0xFF2E3336, chatBackground = 0xFF121416, chatPattern = 0xFF1A1D1F,
            bubbleOut = 0xFF3A3F43, onBubbleOut = 0xFFF1F2F3, bubbleIn = 0xFF202427, onBubbleIn = 0xFFE8EAEB,
            delivered = 0xFFFFB74D, verified = 0xFFFFB74D, warningContainer = 0xFF4A3B10, onWarningContainer = 0xFFFFE9A8, danger = 0xFFFF8A80,
            avatars = listOf(0xFF546E7A, 0xFF8A5A00, 0xFF6D4C41, 0xFF455A64, 0xFF5D4A7A, 0xFF7A3F3F),
        ),
    )

    val Dusk = Palette(
        id = "dusk", name = "Dusk", tagline = "Warm terracotta and rose",
        light = Scheme(
            primary = 0xFFB23A2B, onPrimary = 0xFFFFFFFF, primaryContainer = 0xFFFADDD6, onPrimaryContainer = 0xFF3F0F08,
            background = 0xFFFFFFFF, onBackground = 0xFF231716, surface = 0xFFFAF3F1, onSurface = 0xFF231716, onSurfaceMuted = 0xFF6E5A57,
            outline = 0xFFE6D6D2, chatBackground = 0xFFF3E7E2, chatPattern = 0xFFEAD9D2,
            bubbleOut = 0xFFF7D3CB, onBubbleOut = 0xFF3F0F08, bubbleIn = 0xFFFFFFFF, onBubbleIn = 0xFF231716,
            delivered = 0xFFB23A2B, verified = 0xFF2F6F4F, warningContainer = 0xFFFFF0C2, onWarningContainer = 0xFF4A3500, danger = 0xFFB71C1C,
            avatars = listOf(0xFFB23A2B, 0xFF8A5A9E, 0xFF3D6FA5, 0xFF7A5C1F, 0xFF3F7A4F, 0xFF8F3F5F),
        ),
        dark = Scheme(
            primary = 0xFFFF8A75, onPrimary = 0xFF411107, primaryContainer = 0xFF6B2418, onPrimaryContainer = 0xFFFFDDD6,
            background = 0xFF140D0C, onBackground = 0xFFF2E8E6, surface = 0xFF1D1413, onSurface = 0xFFF2E8E6, onSurfaceMuted = 0xFFB0A09C,
            outline = 0xFF3D2E2B, chatBackground = 0xFF171010, chatPattern = 0xFF211716,
            bubbleOut = 0xFF6B2418, onBubbleOut = 0xFFFFEAE6, bubbleIn = 0xFF2A1D1B, onBubbleIn = 0xFFF2E8E6,
            delivered = 0xFFFF8A75, verified = 0xFF7FD0A4, warningContainer = 0xFF4A3B10, onWarningContainer = 0xFFFFE9A8, danger = 0xFFFF8A80,
            avatars = listOf(0xFFB23A2B, 0xFF8A5A9E, 0xFF3D6FA5, 0xFF7A5C1F, 0xFF3F7A4F, 0xFF8F3F5F),
        ),
    )

    val all: List<Palette> = listOf(Fern, Onion, Midnight, Graphite, Dusk)
    val DEFAULT: Palette = Fern
    fun byId(id: String?): Palette = all.firstOrNull { it.id == id } ?: DEFAULT
}
