package app.nerdchat.ui

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
import app.nerdchat.model.*

@Composable
fun PairScreen(
    onCreateOffer: () -> PairingOffer, onJoin: (link: String, code: String) -> JoinResult,
    onCopy: (String) -> Unit, onPaired: (Int) -> Unit, initialTab: Int = 0, initialOffer: PairingOffer? = null,
) {
    var tab by remember { mutableIntStateOf(initialTab) }
    var offer by remember { mutableStateOf(initialOffer) }
    var link by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
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
                Text("Send the link by any channel. Tell the code by phone or in person: a DIFFERENT channel. The link is useless without the code.", color = NerdTheme.colors.muted)
                val o = offer
                if (o == null) {
                    Button(onClick = { offer = onCreateOffer() }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Create link and code") }
                } else {
                    Card("Link") {
                        Text(o.link, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                        TextButton(onClick = { onCopy(o.link) }) { Text("Copy link") }
                    }
                    Card("Code (say it, never send it with the link)") {
                        Text(o.code.replace('-', ' '), fontFamily = FontFamily.Monospace, fontSize = 30.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth())
                        Text("Valid for ${o.expiresInSeconds / 60} minutes. Keep this screen open until your contact has joined.", color = NerdTheme.colors.muted, fontSize = 13.sp)
                    }
                }
            } else {
                Text("Paste the link you received and type the code you were told.", color = NerdTheme.colors.muted)
                SecureField(link, { link = it; error = null }, "Link (nerdchat:pair/…)", singleLine = false, maxLines = 3, modifier = Modifier.fillMaxWidth())
                SecureField(code, { code = it; error = null }, "Code (10 digits)", numeric = true, modifier = Modifier.fillMaxWidth())
                error?.let { Text(it, color = NerdTheme.colors.danger) }
                Button(onClick = { when (val r = onJoin(link, code)) { is JoinResult.Paired -> onPaired(r.contactId); is JoinResult.Rejected -> error = r.reason } },
                    enabled = link.isNotBlank() && code.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Pair") }
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
