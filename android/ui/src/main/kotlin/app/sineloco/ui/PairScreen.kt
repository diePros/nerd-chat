package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.AppState
import app.sineloco.model.ChatBackend
import app.sineloco.model.PairLink

/**
 * Four ways to pair, every one ending in the same two checks (the in-person question and the safety number):
 *  0 "Show link"     over Tor: a link (any channel) and a code (a DIFFERENT channel); or both as one QR code for the person in front of you
 *  1 "Enter link"    over Tor: the link and the code you were given (or scanned: a `sineloco:` link opened from the camera or another app fills this in)
 *  2 "Contact text"  no network needed: swap contact files as text (share, paste, save, open) and then compare the safety number by voice
 *  3 "Same network"  a direct connection on a private network, NOT through Tor: both devices see each other's address
 * Every way starts with a contact (a fresh key pair for that person), or pairs an EXISTING one again ([existingName]).
 */
@Composable
fun PairScreen(
    state: AppState, backend: ChatBackend, platform: PlatformActions = NoPlatform,
    initialTab: Int = 0, existingName: String? = null, prefill: PairLink? = null, onPrefillUsed: () -> Unit = {},
) {
    var tab by remember { mutableIntStateOf(initialTab) }
    var name by remember(existingName) { mutableStateOf(existingName ?: "") } // pairing AGAIN: the contact exists, its name is fixed
    var created by remember(existingName) { mutableStateOf(existingName != null) } // the contact exists in the core (and is selected there)
    var link by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var started by remember { mutableStateOf(false) }
    var showQr by remember { mutableStateOf(false) }
    var theirs by remember { mutableStateOf("") }
    var ip by remember { mutableStateOf("") }
    var joinAddr by remember { mutableStateOf("") }
    var joinCode by remember { mutableStateOf("") }
    val newName = { if (created) null else name }
    val offer = state.torOffer
    LaunchedEffect(prefill) {
        when (prefill) {
            is PairLink.Tor -> { tab = 1; link = prefill.link; code = prefill.code ?: "" }
            is PairLink.Lan -> { tab = 3; joinAddr = prefill.addr; joinCode = prefill.code ?: "" }
            null -> {}
        }
        if (prefill != null) onPrefillUsed()
    }
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar { Text("Pair a contact", fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 12.dp)) }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(4.dp).horizontalScroll(rememberScrollState())) {
                listOf("Show link", "Enter link", "Contact text", "Same network").forEachIndexed { i, label ->
                    val sel = tab == i
                    Box(Modifier.clip(RoundedCornerShape(20.dp)).background(if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant).clickable { tab = i }.padding(horizontal = 16.dp, vertical = 10.dp), contentAlignment = Alignment.Center) {
                        Text(label, color = if (sel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold, maxLines = 1)
                    }
                }
            }
            val nameField: @Composable () -> Unit = {
                if (existingName == null) SecureField(name, { name = it }, "Contact name (only you see it)", modifier = Modifier.fillMaxWidth())
                else Text("Pairing again with $existingName", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
            }
            val statusLine: @Composable () -> Unit = {
                if (state.status.isNotEmpty()) Text(state.status, color = if (state.statusIsError) SineTheme.colors.danger else SineTheme.colors.muted, fontSize = 14.sp)
            }
            when (tab) {
                0 -> {
                    Text("Send the link by any channel. Tell the code by phone or in person: a DIFFERENT channel. The link is useless without the code.", color = SineTheme.colors.muted)
                    if (offer == null) {
                        if (!started) {
                            nameField()
                            Button(onClick = { started = true; if (!created) { backend.addContact(name); created = true }; backend.startOffer() }, enabled = name.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Create link and code") }
                        } else {
                            Row(verticalAlignment = Alignment.CenterVertically) { CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.5.dp); Spacer(Modifier.width(12.dp)); Text("Waiting for Tor to publish the pairing service…", color = SineTheme.colors.muted) }
                            statusLine()
                            TextButton(onClick = { started = false; backend.cancelPairing() }) { Text("Cancel") }
                        }
                    } else {
                        Card("Link" + (offer.forContact?.let { " for $it" } ?: "")) {
                            Text(offer.link, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                            TextButton(onClick = { platform.copy(offer.link) }) { Text("Copy link") }
                        }
                        Card("Code (say it, never send it with the link)") {
                            Text(offer.code.replace('-', ' '), fontFamily = FontFamily.Monospace, fontSize = 30.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                            Text("Valid for about ${maxOf(1, offer.expiresInSeconds / 60)} minutes. Keep this screen open until your contact has joined.", color = SineTheme.colors.muted, fontSize = 13.sp)
                        }
                        QrSection(PairLink.torQr(offer.link, offer.code), showQr) { showQr = it }
                        TextButton(onClick = { started = false; showQr = false; backend.cancelPairing() }) { Text("Cancel pairing") }
                    }
                }
                1 -> {
                    Text("Paste the link you received and type the code you were told. Or scan the other phone's QR code with your camera app: it opens this screen filled in.", color = SineTheme.colors.muted)
                    nameField()
                    SecureField(link, { link = it }, "Link (sineloco:pair/…)", singleLine = false, maxLines = 3, modifier = Modifier.fillMaxWidth())
                    SecureField(code, { code = it }, "Code (10 digits)", numeric = true, secret = true, modifier = Modifier.fillMaxWidth())
                    if (state.status.isNotEmpty() && state.statusIsError) Text(state.status, color = SineTheme.colors.danger)
                    Button(onClick = { val c = code.toCharArray(); code = ""; if (!created) { backend.addContact(name); created = true }; backend.joinWithLink(link, c) },
                        enabled = name.isNotBlank() && link.isNotBlank() && code.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Pair") }
                }
                2 -> {
                    Text("No network needed. You each show your contact text and send it to the other by a channel you trust (it is not secret, but it shows when you are online), then you each add the text you got. Afterwards compare the safety number by voice.", color = SineTheme.colors.muted)
                    nameField()
                    Button(onClick = { backend.exportMine(newName()); created = true }, enabled = name.isNotBlank() || created, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Show my contact text") }
                    state.exportText?.let { mine ->
                        Card("My contact text") {
                            Text(mine, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurface, maxLines = 8)
                            Row(Modifier.horizontalScroll(rememberScrollState())) {
                                TextButton(onClick = { platform.copy(mine) }) { Text("Copy") }
                                TextButton(onClick = { platform.share(mine) }) { Text("Share…") }
                                TextButton(onClick = { platform.saveText("sineloco-contact.txt", mine) }) { Text("Save as file…") }
                                TextButton(onClick = { backend.clearExport() }) { Text("Done") }
                            }
                        }
                    }
                    SecureField(theirs, { theirs = it }, "Their contact text (paste it here)", singleLine = false, maxLines = 6, modifier = Modifier.fillMaxWidth())
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { platform.pickText { theirs = it } }) { Text("Open file…") }
                        Button(onClick = { backend.importTheirs(newName(), theirs); created = true; theirs = "" }, enabled = theirs.isNotBlank() && (name.isNotBlank() || created)) { Text("Add their contact text") }
                    }
                    statusLine()
                }
                else -> {
                    Card("This is a direct connection, NOT through Tor") {
                        Text("Both devices see each other's address on this network, and so does everyone on it. Use it only on a network you trust (your own Wi-Fi or a hotspot you made), with the other person next to you.", color = SineTheme.colors.muted, fontSize = 13.sp)
                    }
                    nameField()
                    val lan = state.lanOffer
                    if (lan == null) {
                        Text("A. Show a code", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onBackground)
                        val addrs = platform.lanAddresses()
                        if (addrs.isNotEmpty()) Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            addrs.forEach { a -> FilterChip(selected = ip == a, onClick = { ip = a }, label = { Text(a) }) }
                        }
                        SecureField(ip, { ip = it }, "This device's address (192.168.x.x)", modifier = Modifier.fillMaxWidth())
                        Button(onClick = { backend.lanOffer(newName(), "${ip.trim()}:0"); created = true }, enabled = ip.isNotBlank() && (name.isNotBlank() || created), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Open for pairing") }
                    } else {
                        Card("Address and code") {
                            Text(lan.addr, fontFamily = FontFamily.Monospace, fontSize = 20.sp, color = MaterialTheme.colorScheme.onSurface)
                            Text(lan.code, fontFamily = FontFamily.Monospace, fontSize = 30.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                            Text("Tell the other person BOTH, in person. Valid for about ${maxOf(1, lan.expiresInSeconds / 60)} minutes, for ONE attempt.", color = SineTheme.colors.muted, fontSize = 13.sp)
                        }
                        QrSection(PairLink.lanQr(lan.addr, lan.code), showQr) { showQr = it }
                        TextButton(onClick = { showQr = false; backend.cancelPairing() }) { Text("Cancel") }
                    }
                    Text("B. Enter the other device's address and code", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onBackground)
                    SecureField(joinAddr, { joinAddr = it }, "Their address (192.168.x.x:port)", modifier = Modifier.fillMaxWidth())
                    SecureField(joinCode, { joinCode = it }, "Code (10 digits)", numeric = true, secret = true, modifier = Modifier.fillMaxWidth())
                    Button(onClick = { val c = joinCode.toCharArray(); joinCode = ""; backend.lanJoin(newName(), joinAddr.trim(), c); created = true },
                        enabled = joinAddr.isNotBlank() && joinCode.isNotBlank() && (name.isNotBlank() || created), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Pair") }
                    statusLine()
                }
            }
        }
    }
}

/** The QR code of a pairing offer, behind a button: it holds the link AND the code, so it is for the person in front of you only. */
@Composable
private fun QrSection(payload: String, shown: Boolean, onShown: (Boolean) -> Unit) {
    if (!shown) { OutlinedButton(onClick = { onShown(true) }, modifier = Modifier.fillMaxWidth()) { Text("Show as QR code (for someone next to you)") }; return }
    Card("QR code: link and code in one") {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { QrCode(payload, 260.dp) }
        Text("Whoever scans this can pair with you, so show it only to the person in front of you. They scan it with their phone's camera app; it opens Sine Loco with everything filled in.", color = SineTheme.colors.muted, fontSize = 13.sp)
        TextButton(onClick = { onShown(false) }) { Text("Hide") }
    }
}

@Composable
private fun Card(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, fontSize = 14.sp)
        content()
    }
}
