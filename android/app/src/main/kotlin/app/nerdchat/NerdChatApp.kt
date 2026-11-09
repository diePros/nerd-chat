package app.nerdchat

import android.app.Application
import app.nerdchat.model.ChatBackend
import app.nerdchat.model.FakeBackend

/**
 * Owns the backend so it survives the activity being recreated. TODAY this is the in-memory demo backend (any non-empty password opens it,
 * nothing is stored, nothing is sent). The JNI bridge to the Rust core replaces this one line (docs/ANDROID_PORT.md, phase P2/P3).
 */
class NerdChatApp : Application() {
    val backend: ChatBackend = FakeBackend()
}
