package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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

/**
 * Pairing over Tor. Both ways start by creating a contact (a fresh key pair for that person). "Show my link": the core publishes a one-shot
 * service and, when Tor has published it, [AppState.torOffer] carries the link and the code. "Enter a link": the link and the code of the other
 * person. The result arrives as state ([AppState.pairingWaiting] raises the in-person question in [SineApp]).
 */
@Composable
fun PairScreen(
    state: AppState, onOffer: (name: String) -> Unit, onJoin: (name: String, link: String, code: CharArray) -> Unit,
    onCancel: () -> Unit, onCopy: (String) -> Unit, initialTab: Int = 0,
) {
    var tab by remember { mutableIntStateOf(initialTab) }
    var name by remember { mutableStateOf("") }
    var link by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var started by remember { mutableStateOf(false) }
    val offer = state.torOffer
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar { Text("Pair a contact", fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 12.dp)) }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(4.dp)) {
                listOf("Show my link", "Enter a link").forEachIndexed { i, label ->
                    val sel = tab == i
                    Box(Modifier.weight(1f).clip(RoundedCornerShape(20.dp)).background(if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant).clickable { tab = i }.padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
                        Text(label, color = if (sel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
            if (tab == 0) {
                Text("Send the link by any channel. Tell the code by phone or in person: a DIFFERENT channel. The link is useless without the code.", color = SineTheme.colors.muted)
                if (offer == null) {
                    if (!started) {
                        SecureField(name, { name = it }, "Contact name (only you see it)", modifier = Modifier.fillMaxWidth())
                        Button(onClick = { started = true; onOffer(name) }, enabled = name.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Create link and code") }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) { CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.5.dp); Spacer(Modifier.width(12.dp)); Text("Waiting for Tor to publish the pairing service…", color = SineTheme.colors.muted) }
                        if (state.status.isNotEmpty()) Text(state.status, color = if (state.statusIsError) SineTheme.colors.danger else SineTheme.colors.muted, fontSize = 14.sp)
                        TextButton(onClick = { started = false; onCancel() }) { Text("Cancel") }
                    }
                } else {
                    Card("Link" + (offer.forContact?.let { " for $it" } ?: "")) {
                        Text(offer.link, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                        TextButton(onClick = { onCopy(offer.link) }) { Text("Copy link") }
                    }
                    Card("Code (say it, never send it with the link)") {
                        Text(offer.code.replace('-', ' '), fontFamily = FontFamily.Monospace, fontSize = 30.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                        Text("Valid for about ${maxOf(1, offer.expiresInSeconds / 60)} minutes. Keep this screen open until your contact has joined.", color = SineTheme.colors.muted, fontSize = 13.sp)
                    }
                    TextButton(onClick = { started = false; onCancel() }) { Text("Cancel pairing") }
                }
            } else {
                Text("Paste the link you received and type the code you were told.", color = SineTheme.colors.muted)
                SecureField(name, { name = it }, "Contact name (only you see it)", modifier = Modifier.fillMaxWidth())
                SecureField(link, { link = it }, "Link (sineloco:pair/…)", singleLine = false, maxLines = 3, modifier = Modifier.fillMaxWidth())
                SecureField(code, { code = it }, "Code (10 digits)", numeric = true, secret = true, modifier = Modifier.fillMaxWidth())
                if (state.status.isNotEmpty() && state.statusIsError) Text(state.status, color = SineTheme.colors.danger)
                Button(onClick = { val c = code.toCharArray(); code = ""; onJoin(name, link, c) },
                    enabled = name.isNotBlank() && link.isNotBlank() && code.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Pair") }
            }
        }
    }
}

@Composable
private fun Card(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface, fontSize = 14.sp)
        content()
    }
}
