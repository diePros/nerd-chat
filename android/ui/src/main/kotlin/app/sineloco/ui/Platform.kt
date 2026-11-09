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
    /** this device's addresses on private networks (192.168.x.x, 10.x.x.x, 172.16-31.x.x) */
    fun lanAddresses(): List<String> = emptyList()
}

object NoPlatform : PlatformActions
