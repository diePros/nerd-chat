package app.nerdchat.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import app.nerdchat.model.*

private sealed interface Dest {
    data object Unlock : Dest
    data class Main(val tab: Int) : Dest
    data class Chat(val id: Int) : Dest
    data class Details(val id: Int) : Dest
}

/**
 * The whole app. Platform things come in as parameters so these sources stay identical on the desktop preview and on Android:
 * [backHandler] (the system back button), [onCopy] (clipboard, marked sensitive by the host), [onExit] (end the process after panic/purge),
 * [onThemeChanged] (the host may remember the choice).
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
    var dest by remember { mutableStateOf<Dest>(if (startAt != null) Dest.Main(startAt) else Dest.Unlock) }
    var wrong by remember { mutableStateOf(false) }
    val st by backend.state.collectAsState()

    // a panic/purge empties the state: go back to the lock screen at once
    LaunchedEffect(st.unlocked) { if (!st.unlocked && startAt == null) dest = Dest.Unlock }

    backHandler(dest is Dest.Chat || dest is Dest.Details || (dest is Dest.Main && (dest as Dest.Main).tab != 0)) {
        dest = when (val d = dest) { is Dest.Details -> Dest.Chat(d.id); is Dest.Chat -> Dest.Main(0); else -> Dest.Main(0) }
    }
    val panic = { backend.panic(); onExit() }

    NerdTheme(palette, mode) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            when (val d = dest) {
                Dest.Unlock -> UnlockScreen(wrong) { pw -> if (backend.unlock(pw)) { wrong = false; dest = Dest.Main(0) } else wrong = true }
                is Dest.Main -> Column(Modifier.fillMaxSize()) {
                    Box(Modifier.weight(1f)) {
                        when (d.tab) {
                            0 -> ChatListScreen(st.chats, st.tor, st.online, onOpen = { backend.open(it); dest = Dest.Chat(it) }, onPair = { dest = Dest.Main(1) }, onLock = panic)
                            1 -> PairScreen(backend::createPairingOffer, backend::join, onCopy, onPaired = { dest = Dest.Chat(it) })
                            else -> SettingsScreen(palette, mode, st.online,
                                onPalette = { palette = it; onThemeChanged(it, mode) }, onMode = { mode = it; onThemeChanged(palette, it) },
                                onOnline = backend::setOnline, onLock = panic, onPurge = { backend.purge(); onExit() })
                        }
                    }
                    NavigationBar(containerColor = MaterialTheme.colorScheme.background) {
                        listOf(Triple("Chats", NerdIcons.Chat, 0), Triple("Pair", NerdIcons.PersonAdd, 1), Triple("Settings", NerdIcons.Tune, 2)).forEach { (label, icon, i) ->
                            NavigationBarItem(selected = d.tab == i, onClick = { dest = Dest.Main(i) }, icon = { Icon(icon, label, LocalContentColor.current) }, label = { Text(label) })
                        }
                    }
                }
                is Dest.Chat -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                    ChatScreen(c, st.messages[c.id].orEmpty(), st.tor, st.online, onBack = { dest = Dest.Main(0) }, onSend = { backend.send(c.id, it) }, onDetails = { dest = Dest.Details(c.id) })
                } ?: run { dest = Dest.Main(0) }
                is Dest.Details -> st.chats.firstOrNull { it.contact.id == d.id }?.contact?.let { c ->
                    DetailsScreen(c, onBack = { dest = Dest.Chat(c.id) }, onVerified = { backend.markVerified(c.id) })
                } ?: run { dest = Dest.Main(0) }
            }
        }
    }
}
