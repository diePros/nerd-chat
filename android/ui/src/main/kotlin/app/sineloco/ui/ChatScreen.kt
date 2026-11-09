package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.*

private val OutShape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 18.dp, bottomEnd = 4.dp)
private val InShape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 4.dp, bottomEnd = 18.dp)

@Composable
fun ChatScreen(
    contact: Contact, messages: List<Message>, tor: TorState, online: Boolean,
    onBack: () -> Unit, onSend: (String) -> Unit, onDetails: () -> Unit, persist: Persist = Persist.Off,
) {
    var draft by remember { mutableStateOf("") }
    var bannerDismissed by remember(contact.id) { mutableStateOf(false) } // in memory only: it comes back on the next start, nothing is saved
    val list = rememberLazyListState()
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) list.animateScrollToItem(messages.size + 1) }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar {
            IconButton(onClick = onBack) { Icon(SineIcons.Back, "Back", SineTheme.colors.onBar) }
            Row(Modifier.weight(1f).clickable(onClick = onDetails).padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Avatar(contact.name, 42.dp, seed = contact.id, ring = SineTheme.colors.onBar.copy(alpha = 0.7f))
                Spacer(Modifier.width(12.dp))
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(contact.name, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.width(6.dp))
                        if (contact.verified) Icon(SineIcons.Shield, "Verified", SineTheme.colors.onBar, 15.dp)
                    }
                    Text(
                        when { !online -> if (persist != Persist.Off) "You are offline: messages wait, encrypted" else "You are offline"; contact.link == Link.Connected -> "Connected over Tor"; contact.link == Link.Connecting -> "Connecting…"; else -> "Not reachable: messages wait here" },
                        fontSize = 12.sp, color = SineTheme.colors.onBar.copy(alpha = 0.85f),
                    )
                }
            }
        }
        Box(Modifier.weight(1f)) {
            ChatWallpaper()
            LazyColumn(Modifier.fillMaxSize(), state = list, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                item("memory") { Pill(when (persist) {
                    Persist.Off -> "Messages live only in memory on this phone, and only while the app is open."
                    Persist.Outbox -> "Unsent messages are kept encrypted on this phone until they arrive. Everything else lives only in memory."
                    Persist.Day -> "Messages are kept encrypted on this phone for about a day."
                    Persist.Week -> "Messages are kept encrypted on this phone for about a week."
                }) }
                if (!contact.verified && !bannerDismissed) item("verify") { VerifyBanner(onDetails, onLater = { bannerDismissed = true }) }
                items(messages, key = { it.id }) { Bubble(it) }
                item("end") { Spacer(Modifier.height(2.dp)) }
            }
        }
        Composer(draft, { draft = it }, onSend = { onSend(draft); draft = "" })
    }
}

@Composable
private fun Pill(text: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Row(Modifier.clip(RoundedCornerShape(12.dp)).background(SineTheme.colors.warningContainer).padding(horizontal = 12.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(SineIcons.Lock, null, SineTheme.colors.onWarningContainer, 14.dp)
            Spacer(Modifier.width(8.dp))
            Text(text, color = SineTheme.colors.onWarningContainer, fontSize = 12.5.sp)
        }
    }
}

@Composable
private fun VerifyBanner(onCheck: () -> Unit, onLater: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.background).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(SineIcons.Shield, null, SineTheme.colors.muted, 20.dp)
            Spacer(Modifier.width(8.dp))
            Text("Not verified yet", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
        }
        Text("Anyone could be pretending to be this person. Compare the number code once, in person or by phone.", color = SineTheme.colors.muted, fontSize = 14.sp, modifier = Modifier.padding(top = 6.dp))
        Row { TextButton(onClick = onCheck) { Text("Check the code") }; TextButton(onClick = onLater) { Text("Later") } }
    }
}

@Composable
private fun Bubble(m: Message) {
    val col = SineTheme.colors
    val (bg, fg) = if (m.fromMe) col.bubbleOut to col.onBubbleOut else col.bubbleIn to col.onBubbleIn
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.fromMe) Arrangement.End else Arrangement.Start) {
        Row(Modifier.widthIn(max = 320.dp).clip(if (m.fromMe) OutShape else InShape).background(bg).padding(start = 12.dp, end = 10.dp, top = 8.dp, bottom = 6.dp), verticalAlignment = Alignment.Bottom) {
            Text(m.text, color = fg, fontSize = 16.sp, modifier = Modifier.weight(1f, fill = false))
            if (m.fromMe) { Spacer(Modifier.width(8.dp)); DeliveryMark(m.delivery) }
        }
    }
}

/** One check = waiting to be handed over, two = their app has it (NOT "read": there are no read receipts), ! = refused, never sent. */
@Composable
fun DeliveryMark(d: Delivery?) {
    val col = SineTheme.colors
    when (d) {
        Delivery.Queued -> Icon(SineIcons.Check, "Queued", col.muted, 15.dp)
        Delivery.Unconfirmed -> Text("?", color = col.muted, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        Delivery.Delivered -> Box(Modifier.width(21.dp).height(15.dp)) {
            Icon(SineIcons.Check, "Delivered", col.delivered, 15.dp)
            Icon(SineIcons.Check, null, col.delivered, 15.dp, Modifier.padding(start = 6.dp))
        }
        Delivery.Refused -> Text("!", color = col.danger, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        null -> {}
    }
}

@Composable
private fun Composer(draft: String, onChange: (String) -> Unit, onSend: () -> Unit) {
    // the core's draft holds 2048 bytes: refuse here instead of letting the text be cut or the send refused out of sight
    val tooLong = draft.encodeToByteArray().size > 2048
    Row(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background).navigationBarsPadding().imePadding().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.Bottom) {
        SecureField(draft, onChange, if (tooLong) "Too long: 2048 bytes at most" else "Message", singleLine = false, maxLines = 5, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        val on = draft.isNotBlank() && !tooLong
        Box(Modifier.size(50.dp).clip(CircleShape).background(if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline).clickable(enabled = on, onClick = onSend), contentAlignment = Alignment.Center) {
            Icon(SineIcons.Send, "Send", if (on) MaterialTheme.colorScheme.onPrimary else SineTheme.colors.muted)
        }
    }
}
