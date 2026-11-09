package app.sineloco.ui

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
    /** this device's addresses on the Wi-Fi or Ethernet network it is connected to (not a VPN, not mobile data): where a local pairing may be offered */
    fun lanAddresses(): List<String> = emptyList()
    /** is `ip:port` an address ON one of those networks (inside its subnet)? A private address that would be routed somewhere else (a VPN, mobile data) must not be dialled. */
    fun onLink(addr: String): Boolean = true
}

object NoPlatform : PlatformActions
