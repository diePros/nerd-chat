package app.nerdchat.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.nerdchat.model.Link
import app.nerdchat.model.TorState

/** Round avatar with the contact's initial; the colour comes from a hash of the name, so a contact keeps its colour. */
@Composable
fun Avatar(name: String, size: Dp = 48.dp, link: Link? = null, modifier: Modifier = Modifier, seed: Int = name.hashCode(), ring: Color? = null) {
    val colors = NerdTheme.colors.avatars
    val bg = colors[(seed and 0x7fffffff) % colors.size]
    Box(modifier.size(size)) {
        Box(Modifier.size(size).clip(CircleShape).background(bg).then(if (ring != null) Modifier.border(1.5.dp, ring, CircleShape) else Modifier), contentAlignment = Alignment.Center) {
            Text(name.firstOrNull()?.uppercase() ?: "?", color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = (size.value * 0.42f).sp)
        }
        if (link != null) {
            val dot = when (link) { Link.Connected -> MaterialTheme.colorScheme.primary; Link.Connecting -> NerdTheme.colors.muted; Link.Offline -> Color.Transparent }
            if (link != Link.Offline) Box(Modifier.align(Alignment.BottomEnd).size(size * 0.27f).clip(CircleShape).background(MaterialTheme.colorScheme.background).padding(2.dp).clip(CircleShape).background(dot))
        }
    }
}

@Composable
fun Icon(icon: ImageVector, desc: String?, tint: Color = MaterialTheme.colorScheme.onSurface, size: Dp = 24.dp, modifier: Modifier = Modifier) =
    Icon(icon, desc, modifier.size(size), tint)

/** "Tor ready / connecting 40% / offline" chip: always visible, so the user always knows whether anything can leave the phone. */
@Composable
fun TorChip(tor: TorState, online: Boolean, modifier: Modifier = Modifier, onBar: Boolean = false) {
    val (label, base) = when {
        !online -> "Offline" to NerdTheme.colors.muted
        tor is TorState.Ready -> "Tor connected" to MaterialTheme.colorScheme.primary
        tor is TorState.Bootstrapping -> "Tor ${tor.percent}%" to NerdTheme.colors.muted
        tor is TorState.Failed -> "Tor failed" to NerdTheme.colors.danger
        else -> "Tor off" to NerdTheme.colors.muted
    }
    val tint = if (onBar) NerdTheme.colors.onBar else base
    Row(modifier.clip(CircleShape).border(1.dp, tint.copy(alpha = 0.5f), CircleShape).padding(horizontal = 10.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(tint))
        Spacer(Modifier.width(6.dp))
        Text(label, color = tint, fontSize = 12.sp, fontWeight = FontWeight.Medium)
    }
}

/** Faint concentric rings (an onion) tiled over the conversation background: more character than a flat colour, still quiet. */
@Composable
fun ChatWallpaper(modifier: Modifier = Modifier) {
    val bg = NerdTheme.colors.chatBackground; val pat = NerdTheme.colors.chatPattern
    Canvas(modifier.fillMaxSize().clipToBounds().background(bg)) {
        val step = 120.dp.toPx(); val stroke = Stroke(width = 1.5.dp.toPx())
        var y = 0f; var row = 0
        while (y < size.height + step) {
            var x = if (row % 2 == 0) 0f else step / 2
            while (x < size.width + step) {
                for (i in 1..3) drawCircle(pat, radius = i * 9.dp.toPx(), center = Offset(x, y), style = stroke)
                x += step
            }
            y += step * 0.6f; row++
        }
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) =
    Text(text, color = MaterialTheme.colorScheme.primary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, modifier = modifier.padding(horizontal = 20.dp, vertical = 10.dp))
