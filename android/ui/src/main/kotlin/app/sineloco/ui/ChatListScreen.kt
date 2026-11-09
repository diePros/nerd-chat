package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.ChatSummary
import app.sineloco.model.Link
import app.sineloco.model.TorState

/** The coloured bar on top of the main screens and the conversation (the WhatsApp-style header). */
@Composable
fun AppBar(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    Surface(color = SineTheme.colors.bar, contentColor = SineTheme.colors.onBar, shadowElevation = 3.dp, modifier = modifier) {
        Row(Modifier.fillMaxWidth().statusBarsPadding().heightIn(min = 64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically, content = content)
    }
}


@Composable
fun ChatListScreen(
    chats: List<ChatSummary>, tor: TorState, online: Boolean,
    onOpen: (Int) -> Unit, onPair: () -> Unit, onLock: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar {
            Text("Sine Loco", fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 12.dp).weight(1f))
            TorChip(tor, online, onBar = true)
            Box {
                IconButton(onClick = { menu = true }) { Icon(SineIcons.More, "Menu", SineTheme.colors.onBar) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("Wipe now (erase from memory)") }, onClick = { menu = false; onLock() })
                }
            }
        }
        if (chats.isEmpty()) {
            Column(Modifier.fillMaxSize().padding(32.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
                OnionMark(); Spacer(Modifier.height(16.dp))
                Text("No contacts yet", fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
                Text("Pair with someone to start. Nothing is stored on any server.", color = SineTheme.colors.muted, modifier = Modifier.padding(top = 8.dp))
                Button(onClick = onPair, modifier = Modifier.padding(top = 20.dp)) { Text("Pair a contact") }
            }
        } else {
            Box(Modifier.weight(1f)) {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(chats, key = { it.contact.id }) { ChatRow(it, onClick = { onOpen(it.contact.id) }) }
                }
                FloatingActionButton(onClick = onPair, containerColor = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.align(Alignment.BottomEnd).padding(18.dp)) {
                    Icon(SineIcons.PersonAdd, "Pair a contact", MaterialTheme.colorScheme.onPrimary)
                }
            }
        }
    }
}

@Composable
private fun ChatRow(c: ChatSummary, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Avatar(c.contact.name, 54.dp, link = c.contact.link, seed = c.contact.id)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(c.contact.name, fontSize = 17.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, color = MaterialTheme.colorScheme.onSurface)
                Spacer(Modifier.width(6.dp))
                // only the GOOD state is marked in the list: a red warning on every unverified contact, always, is noise that people learn to ignore (the chat and the details say it once)
                if (c.contact.verified) Icon(SineIcons.Shield, "Verified", SineTheme.colors.verified, 15.dp)
            }
            Spacer(Modifier.height(3.dp))
            val sub = c.preview ?: when (c.contact.link) { Link.Connecting -> "Connecting…"; Link.Offline -> "Offline"; Link.Connected -> "Connected" }
            Text(sub, color = SineTheme.colors.muted, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (c.unread > 0) {
            Box(Modifier.defaultMinSize(minWidth = 24.dp, minHeight = 24.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary).padding(horizontal = 7.dp), contentAlignment = Alignment.Center) {
                Text("${c.unread}", color = MaterialTheme.colorScheme.onPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
    }
    HorizontalDivider(Modifier.padding(start = 84.dp), color = MaterialTheme.colorScheme.outline.copy(alpha = 0.6f))
}
