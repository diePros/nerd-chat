package app.sineloco.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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
import app.sineloco.model.Stage

@Composable
fun OnionMark(modifier: Modifier = Modifier) {
    val c = MaterialTheme.colorScheme.primary
    Canvas(modifier.size(96.dp)) {
        val ctr = Offset(size.width / 2, size.height / 2)
        for (i in 1..4) drawCircle(c.copy(alpha = 0.25f + 0.2f * i), radius = size.minDimension / 2 * (i / 4f), center = ctr, style = Stroke(width = 5.dp.toPx()))
        drawCircle(c, radius = size.minDimension / 2 * 0.16f, center = ctr)
    }
}

/**
 * The lock screen and the vault creation. Which step it is comes from the core ([stage]): unlock, choose a password, repeat it, or wait while
 * the (memory-hard) key derivation runs. The status line is the core's own text, so its reasons ("Too short", "did not match") are shown as they are.
 */
@Composable
fun UnlockScreen(stage: Stage, status: String, statusIsError: Boolean, onSubmit: (CharArray) -> Unit) {
    var pw by remember(stage) { mutableStateOf("") }
    val (title, hint, button) = when (stage) {
        Stage.CreatePassword -> Triple("Create your vault", "Choose a password", "Continue")
        Stage.ConfirmPassword -> Triple("Repeat the password", "Repeat the password", "Create vault")
        else -> Triple("Sine Loco", "Vault password", "Unlock")
    }
    Column(Modifier.fillMaxSize().padding(28.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        OnionMark()
        Spacer(Modifier.height(20.dp))
        Text(title, fontSize = 28.sp, lineHeight = 34.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground, textAlign = TextAlign.Center)
        Spacer(Modifier.height(6.dp))
        Text(
            if (stage == Stage.CreatePassword) "At least 12 characters. A long passphrase is best: there is no way to recover it." else "Direct. End-to-end encrypted. Only through Tor.",
            color = SineTheme.colors.muted, textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(32.dp))
        if (stage == Stage.Working) {
            CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(16.dp))
            Text("Deriving the key. This takes a few seconds.", color = SineTheme.colors.muted, textAlign = TextAlign.Center)
        } else {
            SecureField(pw, { pw = it }, hint, secret = true, modifier = Modifier.widthIn(max = 420.dp).fillMaxWidth())
            if (status.isNotEmpty() && statusIsError) Text(status, color = SineTheme.colors.danger, modifier = Modifier.padding(top = 10.dp), textAlign = TextAlign.Center)
            Spacer(Modifier.height(18.dp))
            Button(onClick = { val a = pw.toCharArray(); pw = ""; onSubmit(a) }, enabled = pw.isNotEmpty(), modifier = Modifier.widthIn(max = 420.dp).fillMaxWidth().height(52.dp)) {
                Text(button, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            }
        }
        Spacer(Modifier.height(28.dp))
        Text("No account. No phone number. No server.", color = SineTheme.colors.muted, fontSize = 13.sp)
    }
}
