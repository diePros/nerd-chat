package app.sineloco.ui

import androidx.compose.ui.graphics.ImageBitmap

/**
 * What only the host (the Android activity) can do. These sources stay free of android.* so that they also compile and render on a desktop JVM: the host passes this in.
 * The defaults do nothing, so a preview or a test needs no host.
 */
interface PlatformActions {
    /** copy text to the clipboard, marked sensitive */
    fun copy(text: String) {}
    /** hand a text to the system share sheet */
    fun share(text: String) {}
    /** ask where to save a text file and write it there */
    fun saveText(suggestedName: String, text: String) {}
    /** ask the user to pick a (small) text file and give its content back; nothing is returned when they cancel */
    fun pickText(onText: (String) -> Unit) {}
    /** this host can send and show photos (it has the isolated media process); without it the photo button is not drawn */
    val photos: Boolean get() = false
    /** pick a photo, re-encode it in the isolated process and offer it to contact [contactId] (and to nobody else, whatever chat is open by then) */
    fun pickPhoto(contactId: Int) {}
    /** the received photo of the open chat, decoded in the isolated process; null when it cannot be shown. Called off the main thread by the host, answered on it. */
    fun loadPhoto(onLoaded: (ImageBitmap?) -> Unit) { onLoaded(null) }
    /** ask where to save the received photo and write it there under a neutral random name; what is written is a RE-ENCODED copy (made in the isolated process), never the sender's bytes */
    fun savePhoto() {}
    /** drop every decoded picture (closing the viewer, leaving the chat, locking) */
    fun forgetPhoto() {}
    /** this device's addresses on the Wi-Fi or Ethernet network it is connected to (not a VPN, not mobile data): where a local pairing may be offered */
    fun lanAddresses(): List<String> = emptyList()
    /** is `ip:port` an address ON one of those networks (inside its subnet)? A private address that would be routed somewhere else (a VPN, mobile data) must not be dialled. */
    fun onLink(addr: String): Boolean = true
}

object NoPlatform : PlatformActions
