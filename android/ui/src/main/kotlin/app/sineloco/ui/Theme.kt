package app.sineloco.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp
import app.sineloco.model.Palette
import app.sineloco.model.Palettes
import app.sineloco.model.Scheme

enum class DarkMode { System, Light, Dark }

/** The tokens Material has no slot for (chat bubbles, delivery tint, avatars...). Read with `SineTheme.colors`. */
@Immutable
class SineColors(
    val chatBackground: Color, val chatPattern: Color,
    val bubbleOut: Color, val onBubbleOut: Color, val bubbleIn: Color, val onBubbleIn: Color,
    val delivered: Color, val verified: Color, val muted: Color,
    val warningContainer: Color, val onWarningContainer: Color, val danger: Color,
    val avatars: List<Color>, val dark: Boolean,
    /** the top bar: the palette colour in light mode, a dark surface (with coloured accents) in dark mode */
    val bar: Color, val onBar: Color,
)

private val LocalSineColors = staticCompositionLocalOf<SineColors> { error("SineTheme not provided") }

object SineTheme {
    val colors: SineColors @Composable get() = LocalSineColors.current
}

private fun c(v: Long) = Color(((v and 0xFFFFFFFFL) or 0xFF000000L).toInt())

internal fun Scheme.toSine(dark: Boolean) = SineColors(
    chatBackground = c(chatBackground), chatPattern = c(chatPattern),
    bubbleOut = c(bubbleOut), onBubbleOut = c(onBubbleOut), bubbleIn = c(bubbleIn), onBubbleIn = c(onBubbleIn),
    delivered = c(delivered), verified = c(verified), muted = c(onSurfaceMuted),
    warningContainer = c(warningContainer), onWarningContainer = c(onWarningContainer), danger = c(danger),
    avatars = avatars.map(::c), dark = dark,
    bar = c(if (dark) surface else primary), onBar = c(if (dark) onSurface else onPrimary),
)

@Composable
fun SineTheme(palette: Palette = Palettes.DEFAULT, mode: DarkMode = DarkMode.System, content: @Composable () -> Unit) {
    val dark = when (mode) { DarkMode.System -> isSystemInDarkTheme(); DarkMode.Light -> false; DarkMode.Dark -> true }
    val s = palette.scheme(dark)
    val common = { base: androidx.compose.material3.ColorScheme ->
        base.copy(
            primary = c(s.primary), onPrimary = c(s.onPrimary), primaryContainer = c(s.primaryContainer), onPrimaryContainer = c(s.onPrimaryContainer),
            secondaryContainer = c(s.primaryContainer), onSecondaryContainer = c(s.onPrimaryContainer),
            background = c(s.background), onBackground = c(s.onBackground),
            surface = c(s.background), onSurface = c(s.onSurface), surfaceVariant = c(s.surface), onSurfaceVariant = c(s.onSurfaceMuted),
            surfaceContainer = c(s.surface), surfaceContainerHigh = c(s.surface), surfaceContainerHighest = c(s.surface),
            outline = c(s.outline), outlineVariant = c(s.outline), error = c(s.danger),
        )
    }
    val scheme = if (dark) common(darkColorScheme()) else common(lightColorScheme())
    val shapes = Shapes(small = RoundedCornerShape(10.dp), medium = RoundedCornerShape(16.dp), large = RoundedCornerShape(24.dp))
    CompositionLocalProvider(LocalSineColors provides s.toSine(dark)) {
        MaterialTheme(colorScheme = scheme, shapes = shapes, content = content)
    }
}
