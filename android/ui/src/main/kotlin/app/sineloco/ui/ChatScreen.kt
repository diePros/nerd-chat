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
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.sineloco.model.*

private val OutShape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 18.dp, bottomEnd = 4.dp)
private val InShape = RoundedCornerShape(topStart = 18.dp, topEnd = 18.dp, bottomStart = 4.dp, bottomEnd = 18.dp)

@Composable
fun ChatScreen(
    contact: Contact, messages: List<Message>, tor: TorState, online: Boolean,
    onBack: () -> Unit, onSend: (String) -> Unit, onDetails: () -> Unit, persist: Persist = Persist.Off,
    file: FileState = FileState.None, platform: PlatformActions = NoPlatform, onAnswerFile: (Boolean) -> Unit = {},
) {
    var draft by remember { mutableStateOf("") }
    var bannerDismissed by remember(contact.id) { mutableStateOf(false) } // in memory only: it comes back on the next start, nothing is saved
    val list = rememberLazyListState()
    var viewer by remember(contact.id) { mutableStateOf<ImageBitmap?>(null) }
    var viewing by remember(contact.id) { mutableStateOf(false) }
    // a decoded picture never outlives the chat screen
    DisposableEffect(contact.id) { onDispose { platform.forgetPhoto() } }
    LaunchedEffect(messages.size, file) { if (messages.isNotEmpty() || file != FileState.None) list.animateScrollToItem(messages.size + 2) }
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
                if (file != FileState.None) item("file") {
                    FileCard(file, contact.name, onAnswerFile,
                        onView = { viewing = true; viewer = null; platform.loadPhoto { viewer = it; if (it == null) viewing = false } },
                        onSave = { ext -> platform.savePhoto(ext) })
                }
                item("end") { Spacer(Modifier.height(2.dp)) }
            }
        }
        val canAttach = platform.photos && contact.link == Link.Connected && online && (file == FileState.None || file == FileState.Sent)
        Composer(draft, { draft = it }, onSend = { onSend(draft); draft = "" }, onAttach = if (canAttach) platform::pickPhoto else null)
    }
    if (viewing) PhotoViewer(viewer, onClose = { viewing = false; viewer = null; platform.forgetPhoto() })
}

/** The card of the one photo a chat can have at a time. Photos are NEVER queued, stored or backed up: they exist in memory while the app is unlocked, and "Save" is the user's own act. */
@Composable
private fun FileCard(f: FileState, name: String, onAnswer: (Boolean) -> Unit, onView: () -> Unit, onSave: (String) -> Unit) {
    val col = SineTheme.colors
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surface).padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(SineIcons.Photo, null, col.muted, 20.dp); Spacer(Modifier.width(8.dp))
            Text(when (f) {
                FileState.Preparing -> "Preparing your photo…"
                FileState.Sending -> "Sending your photo…"
                FileState.Sent -> "Photo delivered: $name's app has it"
                is FileState.Offered -> "$name wants to send a photo"
                FileState.Arriving -> "Receiving the photo…"
                is FileState.Received -> if (f.isImage) "Photo received" else "File received (not a picture)"
                FileState.None -> ""
            }, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
        }
        when (f) {
            is FileState.Offered -> {
                Text("Up to about ${f.kib} KiB. It is checked and cleaned here before you can see it, and it only exists in memory until you save it or lock the app.", color = col.muted, fontSize = 14.sp, modifier = Modifier.padding(top = 6.dp))
                Row { TextButton(onClick = { onAnswer(true) }) { Text("Accept") }; TextButton(onClick = { onAnswer(false) }) { Text("Decline") } }
            }
            is FileState.Received -> {
                Text("${f.kib} KiB, kept in memory only.", color = col.muted, fontSize = 14.sp, modifier = Modifier.padding(top = 6.dp))
                Row {
                    if (f.isImage) TextButton(onClick = onView) { Text("View") }
                    TextButton(onClick = { onSave(if (f.isImage) "jpg" else "bin") }) { Text("Save…") }
                    TextButton(onClick = { onAnswer(false) }) { Text("Discard") }
                }
            }
            FileState.Preparing, FileState.Sending, FileState.Arriving -> LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 10.dp))
            else -> {}
        }
    }
}

/** Full screen, black, in memory: the only place a received picture is drawn. */
@Composable
private fun PhotoViewer(image: ImageBitmap?, onClose: () -> Unit) {
    // a dialog is its OWN window: secure it explicitly so that it can never be captured, whatever the default policy is
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnClickOutside = true, securePolicy = androidx.compose.ui.window.SecureFlagPolicy.SecureOn)) {
        Box(Modifier.fillMaxSize().background(androidx.compose.ui.graphics.Color.Black).clickable(onClick = onClose), contentAlignment = Alignment.Center) {
            if (image == null) CircularProgressIndicator()
            else androidx.compose.foundation.Image(image, "Received photo", Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
            IconButton(onClick = onClose, modifier = Modifier.align(Alignment.TopStart).statusBarsPadding()) { Icon(SineIcons.Back, "Close", androidx.compose.ui.graphics.Color.White) }
        }
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
private fun Composer(draft: String, onChange: (String) -> Unit, onSend: () -> Unit, onAttach: (() -> Unit)? = null) {
    // the core's draft holds 2048 bytes: refuse here instead of letting the text be cut or the send refused out of sight
    val tooLong = draft.encodeToByteArray().size > 2048
    Row(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background).navigationBarsPadding().imePadding().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.Bottom) {
        if (onAttach != null) { IconButton(onClick = onAttach, modifier = Modifier.size(50.dp)) { Icon(SineIcons.Photo, "Send a photo", SineTheme.colors.muted) }; Spacer(Modifier.width(4.dp)) }
        SecureField(draft, onChange, if (tooLong) "Too long: 2048 bytes at most" else "Message", singleLine = false, maxLines = 5, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(8.dp))
        val on = draft.isNotBlank() && !tooLong
        Box(Modifier.size(50.dp).clip(CircleShape).background(if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline).clickable(enabled = on, onClick = onSend), contentAlignment = Alignment.Center) {
            Icon(SineIcons.Send, "Send", if (on) MaterialTheme.colorScheme.onPrimary else SineTheme.colors.muted)
        }
    }
}
