package app.sineloco.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.sineloco.model.*

private sealed interface Dest {
    data class Main(val tab: Int) : Dest
    data class Chat(val id: Int) : Dest
    data class Details(val id: Int) : Dest
}

/**
 * The whole app. Platform things come in as parameters so these sources stay identical on the desktop preview and on Android:
 * [backHandler] (the system back button), [onCopy] (clipboard, marked sensitive by the host), [onExit] (end the process after panic/purge),
 * [onThemeChanged] (the host may remember the choice).
 *
 * Which screen shows is decided by the core's [AppState.stage]: anything but [Stage.Ready] is the lock / vault-creation screen, and
 * [Stage.Wiped] (panic or purge happened) ends the process.
 */
@Composable
fun SineApp(
    backend: ChatBackend,
    initialPalette: Palette = Palettes.DEFAULT, initialMode: DarkMode = DarkMode.System,
    onThemeChanged: (Palette, DarkMode) -> Unit = { _, _ -> },
    backHandler: @Composable (enabled: Boolean, onBack: () -> Unit) -> Unit = { _, _ -> },
    onCopy: (String) -> Unit = {},
    platform: PlatformActions = NoPlatform,
    /** a `sineloco:` link opened from another app or scanned from a QR code: it only PRE-FILLS the pairing form, the user still presses Pair */
    incomingLink: PairLink? = null,
    onIncomingLinkUsed: () -> Unit = {},
    onExit: () -> Unit = {},
    startAt: Int? = null,
) {
    var palette by remember { mutableStateOf(initialPalette) }
    var mode by remember { mutableStateOf(initialMode) }
    var dest by remember { mutableStateOf<Dest>(Dest.Main(startAt ?: 0)) }
    var pairAgain by remember { mutableStateOf<Pair<Int, String>?>(null) } // in memory only: the contact whose keys were just forgotten, to pair with again
    LaunchedEffect(dest) { if (dest != Dest.Main(1)) pairAgain = null }
    val st by backend.state.collectAsState()
    // a pairing link arrived (QR code, another app): show the pairing screen as soon as the app is usable (a locked app keeps it in memory until the password is typed)
    LaunchedEffect(incomingLink, st.stage) { if (incomingLink != null && st.stage == Stage.Ready) dest = Dest.Main(1) }

    // a wipe (panic or purge) ends the process; leaving Ready for any other reason shows the lock screen again from the list
    LaunchedEffect(st.stage) {
        if (st.stage == Stage.Wiped) onExit()
        if (st.stage != Stage.Ready) dest = Dest.Main(0)
    }

    backHandler(st.stage == Stage.Ready && (dest is Dest.Chat || dest is Dest.Details || (dest is Dest.Main && (dest as Dest.Main).tab != 0))) {
        dest = when (val d = dest) { is Dest.Details -> { backend.open(d.id); Dest.Chat(d.id) }; is Dest.Chat -> { backend.closeChat(); Dest.Main(0) }; else -> Dest.Main(0) }
    }
    val panic = { backend.panic() }

    SineTheme(palette, mode) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            if (st.stage != Stage.Ready) {
                if (st.stage == Stage.Wiped) Box(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background))
                else UnlockScreen(st.stage, st.status, st.statusIsError, backend::submitPassword)
                return@Surface
            }
            Column(Modifier.fillMaxSize()) {
                st.alerts.firstOrNull()?.let { AlertBanner(it, st.alerts.size - 1, backend::acknowledgeAlert) }
                // the bridge refused a step (and the core's own reason, if it has one): shown for a few seconds, never silently dropped
                st.rejected?.let { r -> NoticeBanner(if (st.statusIsError && st.status.isNotBlank()) "$r\n${st.status}" else r) }
                Box(Modifier.weight(1f)) {
                    when (val d = dest) {
                        is Dest.Main -> Column(Modifier.fillMaxSize()) {
                            Box(Modifier.weight(1f)) {
                                when (d.tab) {
                                    0 -> ChatListScreen(st.chats, st.tor, st.online, onOpen = { backend.open(it); dest = Dest.Chat(it) }, onPair = { dest = Dest.Main(1) }, onLock = panic)
                                    1 -> PairScreen(st, backend, platform, existingId = pairAgain?.first, existingName = pairAgain?.second, prefill = incomingLink, onPrefillUsed = onIncomingLinkUsed)
                                    else -> SettingsScreen(palette, mode, st.online, st.tor, st.persist,
                                        onPalette = { palette = it; onThemeChanged(it, mode) }, onMode = { mode = it; onThemeChanged(palette, it) },
                                        onOnline = backend::setOnline, onPersist = backend::setPersist, onLock = panic, onPurge = { backend.purge() })
                                }
                            }
                            NavigationBar(containerColor = MaterialTheme.colorScheme.background) {
                                listOf(Triple("Chats", SineIcons.Chat, 0), Triple("Pair", SineIcons.PersonAdd, 1), Triple("Settings", SineIcons.Tune, 2)).forEach { (label, icon, i) ->
                                    NavigationBarItem(selected = d.tab == i, onClick = { dest = Dest.Main(i) }, icon = { Icon(icon, label, LocalContentColor.current) }, label = { Text(label) })
                                }
                            }
                        }
                        is Dest.Chat -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                            ChatScreen(c, st.messages[c.id].orEmpty(), st.tor, st.online, onBack = { backend.closeChat(); dest = Dest.Main(0) }, onSend = { backend.send(c.id, it) }, onDetails = { dest = Dest.Details(c.id) }, persist = st.persist, file = st.file, platform = platform, onAnswerFile = backend::answerFile)
                        } ?: run { dest = Dest.Main(0) }
                        is Dest.Details -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                            DetailsScreen(c, st.verifyNumber, onBack = { backend.open(c.id); dest = Dest.Chat(c.id) }, onStartVerify = { backend.startVerify(c.id) }, onConfirmVerify = backend::confirmVerify, onDelete = { backend.deleteContact(c.id); dest = Dest.Main(0) }, onPairAgain = { backend.repairContact(c.id); pairAgain = c.id to c.name; dest = Dest.Main(1) })
                        } ?: run { dest = Dest.Main(0) }
                    }
                }
            }
            if (st.pairingWaiting) PairingCheckDialog(st.pairingSn, onIdentical = backend::confirmPairingNumber, onLater = backend::skipPairingCheck, onDifferent = backend::discardPairing)
        }
    }
}

@Composable
private fun NoticeBanner(text: String) {
    Surface(color = SineTheme.colors.warningContainer, contentColor = SineTheme.colors.onWarningContainer) {
        Text(text, fontSize = 14.sp, modifier = Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp))
    }
}

@Composable
private fun AlertBanner(text: String, more: Int, onAck: () -> Unit) {
    Surface(color = SineTheme.colors.warningContainer, contentColor = SineTheme.colors.onWarningContainer) {
        Row(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(text, fontSize = 14.sp)
                if (more > 0) Text("+$more more", fontSize = 12.sp)
            }
            TextButton(onClick = onAck) { Text("Got it", color = SineTheme.colors.onWarningContainer) }
        }
    }
}

/**
 * After a pairing, ALWAYS the same check, whatever way it came (a QR code or a link can come from anybody, a contact text from any channel): the two phones must show the SAME safety
 * number, side by side. Only then is the contact marked verified. "Different" saves nothing: either somebody is in between or the other side did not finish (the last message of a pairing
 * can get lost, then only one side has finished).
 */
@Composable
private fun PairingCheckDialog(number: String?, onIdentical: () -> Unit, onLater: () -> Unit, onDifferent: () -> Unit) {
    AlertDialog(
        onDismissRequest = onLater,
        title = { Text("Pairing finished: compare the number") },
        text = { Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(number?.replace(" ", "  ") ?: "", fontFamily = FontFamily.Monospace, fontSize = 20.sp, fontWeight = FontWeight.Medium)
            Text("Hold the two phones side by side (or read it out by voice). It must be exactly the same on both. If the other phone shows an error, or a different number, choose \"Different\": nothing is saved and you can pair again.", color = SineTheme.colors.muted, fontSize = 14.sp)
        } },
        confirmButton = { Row { TextButton(onClick = onDifferent) { Text("Different") }; TextButton(onClick = onLater) { Text("Compare later") }; TextButton(onClick = onIdentical) { Text("Identical") } } },
    )
}
