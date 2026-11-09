package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.Palette
import app.sineloco.model.Palettes
import app.sineloco.model.Persist
import app.sineloco.model.TorState

@Composable
fun SettingsScreen(
    palette: Palette, mode: DarkMode, online: Boolean, tor: TorState = TorState.Off, persist: Persist = Persist.Off,
    onPalette: (Palette) -> Unit, onMode: (DarkMode) -> Unit, onOnline: (Boolean) -> Unit, onPersist: (Persist) -> Unit = {},
    onLock: () -> Unit, onPurge: () -> Unit,
) {
    var confirmPurge by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar { Text("Settings", fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 12.dp)) }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
            SectionLabel("Appearance")
            Row(Modifier.padding(horizontal = 16.dp).fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(4.dp)) {
                DarkMode.entries.forEach { m ->
                    val sel = m == mode
                    Box(Modifier.weight(1f).clip(RoundedCornerShape(20.dp)).background(if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant).clickable { onMode(m) }.padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
                        Text(m.name, color = if (sel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            Palettes.all.forEach { p -> PaletteCard(p, selected = p.id == palette.id, dark = SineTheme.colors.dark) { onPalette(p) } }

            SectionLabel("Privacy")
            ToggleRow("Be reachable", "Runs Tor and your onion services so contacts can reach you. Off = nothing leaves this phone.", online, onOnline)
            when (tor) {
                is TorState.Failed -> Text("Tor could not start: ${tor.reason}", color = SineTheme.colors.danger, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 20.dp))
                is TorState.Bootstrapping -> Text("Tor is starting: ${tor.percent}%", color = SineTheme.colors.muted, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 20.dp))
                TorState.Ready -> Text("Tor is connected.", color = SineTheme.colors.muted, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 20.dp))
                TorState.Off -> {}
            }
            PersistPicker(persist, onPersist)
            InfoRow("Bridges", "Not configured. Needed where Tor is blocked (comes with the Tor integration).")
            InfoRow("Presence", "Online only while the app is open. A phone that is always on shows a daily pattern to anyone who knows your address.")

            SectionLabel("Danger zone")
            Button(onClick = onLock, modifier = Modifier.padding(horizontal = 16.dp).fillMaxWidth().height(50.dp)) { Text("Wipe now (erase from memory)") }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = { confirmPurge = true }, modifier = Modifier.padding(horizontal = 16.dp).fillMaxWidth().height(50.dp)) { Text("Purge everything…", color = SineTheme.colors.danger) }
            Spacer(Modifier.height(24.dp))
        }
    }
    if (confirmPurge) AlertDialog(
        onDismissRequest = { confirmPurge = false },
        title = { Text("Purge everything?") },
        text = { Text("This overwrites and deletes the vault, your keys and every contact. It cannot be undone.") },
        confirmButton = { TextButton(onClick = { confirmPurge = false; onPurge() }) { Text("Purge", color = SineTheme.colors.danger) } },
        dismissButton = { TextButton(onClick = { confirmPurge = false }) { Text("Cancel") } },
    )
}

@Composable
private fun PaletteCard(p: Palette, selected: Boolean, dark: Boolean, onClick: () -> Unit) {
    val s = p.scheme(dark)
    val shape = RoundedCornerShape(16.dp)
    Row(
        Modifier.padding(horizontal = 16.dp, vertical = 5.dp).fillMaxWidth().clip(shape)
            .border(if (selected) 2.dp else 1.dp, if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline, shape)
            .clickable(onClick = onClick).padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy((-8).dp)) {
            listOf(s.primary, s.bubbleOut, s.chatBackground, s.avatars[1]).forEach {
                Box(Modifier.size(30.dp).clip(CircleShape).border(2.dp, MaterialTheme.colorScheme.background, CircleShape).background(Color(((it and 0xFFFFFFFFL) or 0xFF000000L).toInt())))
            }
        }
        Spacer(Modifier.width(18.dp))
        Column(Modifier.weight(1f)) {
            Text(p.name, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, color = MaterialTheme.colorScheme.onSurface)
            Text(p.tagline, color = SineTheme.colors.muted, fontSize = 13.sp)
        }
        if (selected) Icon(SineIcons.Check, "Selected", MaterialTheme.colorScheme.primary)
    }
}

/** What this device keeps of the conversations. The text under it is the honest one: nothing here is "disappearing". */
@Composable
private fun PersistPicker(persist: Persist, onPersist: (Persist) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)) {
        Text("Messages on this phone", fontSize = 16.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface)
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(4.dp)) {
            listOf(Persist.Off to "Nothing", Persist.Outbox to "Unsent", Persist.Day to "1 day", Persist.Week to "7 days").forEach { (p, label) ->
                val sel = p == persist
                Box(Modifier.weight(1f).clip(RoundedCornerShape(20.dp)).background(if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant).clickable { onPersist(p) }.padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
                    Text(label, color = if (sel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            when (persist) {
                Persist.Off -> "Nothing is kept: messages exist only in memory and are gone when the app ends."
                Persist.Outbox -> "Only messages you sent that your contact has not confirmed yet are kept, encrypted, until they arrive. You can write while offline."
                Persist.Day -> "Messages are kept on this phone for about a day (24-30 hours), encrypted with your vault. Your contact's phone follows its own setting."
                Persist.Week -> "Messages are kept on this phone for about a week, encrypted with your vault. Your contact's phone follows its own setting."
            },
            color = SineTheme.colors.muted, fontSize = 13.sp,
        )
        if (persist.ordinal > 0) Text(
            "Anyone with your phone and your password can read what is kept. A deleted message may survive in the phone's storage until it is overwritten.",
            color = SineTheme.colors.muted, fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp),
        )
    }
}

@Composable
private fun ToggleRow(title: String, text: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface)
            Text(text, color = SineTheme.colors.muted, fontSize = 13.sp)
        }
        Spacer(Modifier.width(12.dp))
        Switch(checked = value, onCheckedChange = onChange)
    }
}

@Composable
private fun InfoRow(title: String, text: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)) {
        Text(title, fontSize = 16.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface)
        Text(text, color = SineTheme.colors.muted, fontSize = 13.sp)
    }
}
