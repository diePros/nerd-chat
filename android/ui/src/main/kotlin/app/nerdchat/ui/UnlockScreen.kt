package app.nerdchat.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun OnionMark(modifier: Modifier = Modifier) {
    val c = MaterialTheme.colorScheme.primary
    Canvas(modifier.size(96.dp)) {
        val ctr = Offset(size.width / 2, size.height / 2)
        for (i in 1..4) drawCircle(c.copy(alpha = 0.25f + 0.2f * i), radius = size.minDimension / 2 * (i / 4f), center = ctr, style = Stroke(width = 5.dp.toPx()))
        drawCircle(c, radius = size.minDimension / 2 * 0.16f, center = ctr)
    }
}

@Composable
fun UnlockScreen(wrongPassword: Boolean, onUnlock: (CharArray) -> Unit) {
    var pw by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        OnionMark()
        Spacer(Modifier.height(20.dp))
        Text("Nerd-chat", fontSize = 30.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground)
        Spacer(Modifier.height(6.dp))
        Text("Direct. End-to-end encrypted. Only through Tor.", color = NerdTheme.colors.muted, textAlign = TextAlign.Center)
        Spacer(Modifier.height(32.dp))
        SecureField(pw, { pw = it }, "Vault password", secret = true, modifier = Modifier.widthIn(max = 420.dp).fillMaxWidth())
        if (wrongPassword) Text("That password did not open the vault.", color = NerdTheme.colors.danger, modifier = Modifier.padding(top = 10.dp))
        Spacer(Modifier.height(18.dp))
        Button(onClick = { val a = pw.toCharArray(); pw = ""; onUnlock(a) }, enabled = pw.isNotEmpty(), modifier = Modifier.widthIn(max = 420.dp).fillMaxWidth().height(52.dp)) {
            Text("Unlock", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(28.dp))
        Text("No account. No phone number. No server.", color = NerdTheme.colors.muted, fontSize = 13.sp)
    }
}
