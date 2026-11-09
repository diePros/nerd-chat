package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.Contact
import app.sineloco.model.Link

/** The "nerd panel" of the desktop GUI, for one contact: safety number, connection, address, role. */
@Composable
fun DetailsScreen(contact: Contact, verifyNumber: String?, onBack: () -> Unit, onStartVerify: () -> Unit, onConfirmVerify: (Boolean) -> Unit) {
    if (verifyNumber != null) VerifyDialog(verifyNumber, onConfirmVerify)
    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        AppBar {
            IconButton(onClick = onBack) { Icon(SineIcons.Back, "Back", SineTheme.colors.onBar) }
            Text("Contact details", fontSize = 20.sp, fontWeight = FontWeight.Bold)
        }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Avatar(contact.name, 88.dp, seed = contact.id)
            Text(contact.name, fontSize = 24.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (contact.verified) SineIcons.Shield else SineIcons.Warning, null, if (contact.verified) SineTheme.colors.verified else SineTheme.colors.danger, 18.dp)
                Spacer(Modifier.width(6.dp))
                Text(if (contact.verified) "Verified" else "Not verified", color = if (contact.verified) SineTheme.colors.verified else SineTheme.colors.danger, fontWeight = FontWeight.SemiBold)
            }
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Safety number", fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
                contact.safetyNumber.chunked(3).forEach { row ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                        row.forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 22.sp, fontWeight = FontWeight.Medium, color = MaterialTheme.colorScheme.onSurface) }
                    }
                }
                Text("Compare these numbers with your contact, in person or by phone. If they match, nobody is in between.", color = SineTheme.colors.muted, fontSize = 13.sp, textAlign = TextAlign.Center)
                if (!contact.paired) Text("Not paired yet: there is no safety number until pairing has finished.", color = SineTheme.colors.muted, fontSize = 13.sp, textAlign = TextAlign.Center)
                else if (!contact.verified) Button(onClick = onStartVerify, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text("Compare the numbers…") }
            }
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surfaceVariant).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row3("Connection", when (contact.link) { Link.Connected -> "Connected over Tor"; Link.Connecting -> "Connecting…"; Link.Offline -> "Not reachable" })
                if (contact.onionShort.isNotEmpty()) Row3("Address", contact.onionShort)
                Row3("Role", if (contact.weHost) "You host for this contact while online" else "You only dial this contact")
            }
        }
    }
}

@Composable
private fun VerifyDialog(number: String, onResult: (Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = { onResult(false) },
        title = { Text("Do the numbers match?") },
        text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(number, fontFamily = FontFamily.Monospace, fontSize = 20.sp, fontWeight = FontWeight.Medium)
            Text("Ask your contact to read THEIR screen to you, in person or by phone. Only if every group is identical is nobody in between.", color = SineTheme.colors.muted, fontSize = 14.sp)
        } },
        confirmButton = { TextButton(onClick = { onResult(true) }) { Text("They match") } },
        dismissButton = { TextButton(onClick = { onResult(false) }) { Text("They differ") } },
    )
}

@Composable
private fun Row3(k: String, v: String) {
    Column { Text(k, color = SineTheme.colors.muted, fontSize = 12.sp); Text(v, color = MaterialTheme.colorScheme.onSurface, fontSize = 16.sp) }
}
