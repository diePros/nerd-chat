package app.nerdchat.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.nerdchat.model.*

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
fun NerdApp(
    backend: ChatBackend,
    initialPalette: Palette = Palettes.DEFAULT, initialMode: DarkMode = DarkMode.System,
    onThemeChanged: (Palette, DarkMode) -> Unit = { _, _ -> },
    backHandler: @Composable (enabled: Boolean, onBack: () -> Unit) -> Unit = { _, _ -> },
    onCopy: (String) -> Unit = {},
    onExit: () -> Unit = {},
    startAt: Int? = null,
) {
    var palette by remember { mutableStateOf(initialPalette) }
    var mode by remember { mutableStateOf(initialMode) }
    var dest by remember { mutableStateOf<Dest>(Dest.Main(startAt ?: 0)) }
    val st by backend.state.collectAsState()

    // a wipe (panic or purge) ends the process; leaving Ready for any other reason shows the lock screen again from the list
    LaunchedEffect(st.stage) {
        if (st.stage == Stage.Wiped) onExit()
        if (st.stage != Stage.Ready) dest = Dest.Main(0)
    }

    backHandler(st.stage == Stage.Ready && (dest is Dest.Chat || dest is Dest.Details || (dest is Dest.Main && (dest as Dest.Main).tab != 0))) {
        dest = when (val d = dest) { is Dest.Details -> { backend.open(d.id); Dest.Chat(d.id) }; is Dest.Chat -> { backend.closeChat(); Dest.Main(0) }; else -> Dest.Main(0) }
    }
    val panic = { backend.panic() }

    NerdTheme(palette, mode) {
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
                                    1 -> PairScreen(st,
                                        onOffer = { name -> backend.addContact(name); backend.startOffer() },
                                        onJoin = { name, link, code -> backend.addContact(name); backend.joinWithLink(link, code) },
                                        onCancel = backend::cancelPairing, onCopy = onCopy)
                                    else -> SettingsScreen(palette, mode, st.online, st.tor, st.persist,
                                        onPalette = { palette = it; onThemeChanged(it, mode) }, onMode = { mode = it; onThemeChanged(palette, it) },
                                        onOnline = backend::setOnline, onPersist = backend::setPersist, onLock = panic, onPurge = { backend.purge() })
                                }
                            }
                            NavigationBar(containerColor = MaterialTheme.colorScheme.background) {
                                listOf(Triple("Chats", NerdIcons.Chat, 0), Triple("Pair", NerdIcons.PersonAdd, 1), Triple("Settings", NerdIcons.Tune, 2)).forEach { (label, icon, i) ->
                                    NavigationBarItem(selected = d.tab == i, onClick = { dest = Dest.Main(i) }, icon = { Icon(icon, label, LocalContentColor.current) }, label = { Text(label) })
                                }
                            }
                        }
                        is Dest.Chat -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                            ChatScreen(c, st.messages[c.id].orEmpty(), st.tor, st.online, onBack = { backend.closeChat(); dest = Dest.Main(0) }, onSend = { backend.send(c.id, it) }, onDetails = { dest = Dest.Details(c.id) }, persist = st.persist)
                        } ?: run { dest = Dest.Main(0) }
                        is Dest.Details -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                            DetailsScreen(c, st.verifyNumber, onBack = { backend.open(c.id); dest = Dest.Chat(c.id) }, onStartVerify = { backend.startVerify(c.id) }, onConfirmVerify = backend::confirmVerify)
                        } ?: run { dest = Dest.Main(0) }
                    }
                }
            }
            if (st.pairingWaiting) InPersonDialog(onAnswer = backend::answerInPerson)
        }
    }
}

@Composable
private fun NoticeBanner(text: String) {
    Surface(color = NerdTheme.colors.warningContainer, contentColor = NerdTheme.colors.onWarningContainer) {
        Text(text, fontSize = 14.sp, modifier = Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp))
    }
}

@Composable
private fun AlertBanner(text: String, more: Int, onAck: () -> Unit) {
    Surface(color = NerdTheme.colors.warningContainer, contentColor = NerdTheme.colors.onWarningContainer) {
        Row(Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(text, fontSize = 14.sp)
                if (more > 0) Text("+$more more", fontSize = 12.sp)
            }
            TextButton(onClick = onAck) { Text("Got it", color = NerdTheme.colors.onWarningContainer) }
        }
    }
}

/** The question the core asks after a pairing: the answer decides the trust level (a "yes" for a code that travelled over a weak channel would be a lie). */
@Composable
private fun InPersonDialog(onAnswer: (Boolean) -> Unit) {
    AlertDialog(
        onDismissRequest = { onAnswer(false) },
        title = { Text("Pairing finished") },
        text = { Text("Did you exchange the code in person or by a voice call you trust? If it travelled in a message, answer No: you can verify the safety number later.") },
        confirmButton = { TextButton(onClick = { onAnswer(true) }) { Text("Yes, in person") } },
        dismissButton = { TextButton(onClick = { onAnswer(false) }) { Text("No") } },
    )
}
