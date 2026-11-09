# Sine Loco for Android (Kotlin, native)

The third native front end next to the terminal UI and the Linux GUI. Kotlin + Jetpack Compose, a WhatsApp-style layout (chat list,
bubbles, delivery marks, a coloured top bar) with the project's privacy rules kept: **no timestamps, no read receipts, no typing
indicators, no presence beyond "connected over Tor"** (docs/DELIVERY.md). Focus: anonymity on the network first.

> **Status: the app runs on the real Rust core; tor is embedded and reaches "Tor connected" on the x86_64 emulator (Android 16); NOT yet tried on a real phone.** The screens talk to `sine-loco-app` through a JNI bridge
> (`crates/android`): vault creation and unlock (the real Argon2 key derivation), contacts, the chat engine, pairing over Tor, verification,
> panic and purge are the core's own code. `libtor.so` (C tor 0.4.9.16 with OpenSSL 3.5.9 and libevent, built by `scripts/build-tor-android.sh` before Gradle, not committed) is started as a child
> process by the core. The build declares `INTERNET` for tor only. Session rules: leaving the screen (home, recents, screen off) LOCKS the app (it keeps running; the password is asked again, the core hands out no contact or message data meanwhile); A locked app erases itself from memory after 8 hours locked (the clock includes sleep) or after 5 wrong lock passwords (the files stay; this is a panic, not a purge). Back from the first screen locks and sends the app away; swipe-away and exit WIPE (core panic, tor killed, process ends). "Go offline" works without the password and cancels a tor start. Foreground service: `ConnectionService` (type `remoteMessaging`, one generic lock-screen-secret, local-only notification "Running" with a "Go offline" button) runs while online with an unlocked vault, so the app and tor survive in the background; swiping the app out of recents wipes RAM and stops tor. Verified on the emulator (Android 16). Network changes: the app tells the core when the phone's network goes away or comes back (tor is paused with `DisableNetwork`, resumed after a random 3-15 s; the UI says "No network"). NOT done: bridges, battery-optimisation guidance, cancelling a tor start (the core refuses "offline" while starting), a run on a real phone.
> `-Pdemo` builds an in-memory demo backend instead (no Rust, any 12+ character password) for UI work.

Setting this up on a new machine (SDK, wrapper, signing, phone install, where to continue): **docs/ANDROID_DEV_SETUP.md**.

## Layout
| Module | What | Builds without the Android SDK |
|---|---|---|
| `model/` | data model, the state-driven `ChatBackend` contract, `RustBackend` (JNI), `FakeBackend`, JSON snapshot parser, **colour palettes** and their contrast tests, and an end-to-end JNI test against the real core | yes (the JNI test needs `cargo`) |
| `ui/` | all Compose screens as plain JVM Compose + a test that renders them to PNG | yes |
| `app/` | the Android app: `MainActivity` (FLAG_SECURE, no backup, sensitive clipboard), manifest, icon. It compiles the **same source files as `ui/`** against androidx Compose, and builds + packages the Rust library for each ABI | no (needs `ANDROID_HOME`, the NDK and `cargo`) |
| `../crates/android` | the Rust side: a command layer over the core's key-driven state machine, the JSON snapshot, four JNI exports (`nInit`, `nCall`, and `nSendFile` / `nFileBytes` for photo bytes) | n/a (Rust) |

Rule for `ui/src/main`: only APIs that exist in both JetBrains Compose (desktop) and androidx Compose. Platform things (back button,
clipboard, process exit) are passed in by the host. The desktop compile therefore proves the Android sources too.

## Build and test
```bash
cd android
./gradlew :model:test :ui:test                 # 27 tests; builds the host bridge library and runs the REAL JNI end-to-end test; screenshots in ui/build/shots/
ANDROID_HOME=~/android-sdk ./gradlew :app:assembleDebug     # builds libsineloco_bridge.so for arm64-v8a + x86_64 with cargo and the NDK, packages it
ANDROID_HOME=~/android-sdk ./gradlew :app:assembleRelease   # unsigned; sign with SINELOCO_KEYSTORE* (see app/build.gradle.kts)
./gradlew :app:assembleDebug -Pdemo                         # demo backend (in-memory), no Rust involved at runtime
cargo test --workspace --locked                             # the Rust side, from the repository root
```
Toolchain (verified 2026-11-09): Gradle 9.9.0 (wrapper), AGP 9.5.1, Kotlin 2.4.21, Compose BOM 2026.09.00 / Compose Multiplatform 1.12.2,
compileSdk 37 (SDK platform `android-37.0`), minSdk 29, targetSdk 36, NDK r29 (`29.0.14206865`), Rust 1.98.1 (`rust-toolchain.toml`), JDK 21.

## How the app talks to the core
`RustBackend` (Kotlin) -> `NativeBridge` (JNI, 4 functions: `nInit`, `nCall`, `nSendFile`, `nFileBytes`) -> `Bridge::call(op, arg)` (Rust) -> `App::handle(Key)` (the same
state machine as the terminal and the Linux GUI) -> a JSON snapshot back. All calls run on ONE thread; a ticker polls the core (key derivation,
Tor start, incoming messages and confirmations arrive by polling). The bridge GUARDS what the screens may do: text reaches the core only where the
core itself takes text, only an allowlist of one-letter commands exists (no quit, no files, no local link), and a message over the compose limit is
refused instead of silently truncated. Passwords and the pairing code travel as `char[]`; the Kotlin array and the Rust copy are wiped, but the snapshot text (chat lines, the pairing code on screen) is copied into Java strings that cannot be wiped, and the `jni` crate keeps one unwiped Rust-side copy per snapshot (tracker R32-B3).

## Changing the colours
All palettes are in **`model/src/main/kotlin/app/sineloco/model/Palettes.kt`**: one block per palette, light and dark scheme, plain hex.
Edit a value, run `./gradlew :model:test`: `PaletteContrastTest` fails if any text/background pair drops below WCAG AA (4.5:1) or a
bubble disappears into the conversation background. Add a palette = add a block and list it in `Palettes.all`. The user picks one in
Settings (stored as an id in a plain preference: it is only a colour). Palettes: Fern (default), Onion, Midnight, Graphite, Dusk.
Look at `design/*.png` (rendered from the real screens).

## What is deliberately in place already
`INTERNET` only for the embedded tor · `allowBackup=false` and empty backup/transfer rules · `FLAG_SECURE` (no screenshots, blank recents
thumbnail) · clipboard copies marked sensitive · no analytics, no push, no Google services · launcher icon independent of the palette ·
arm64-v8a + x86_64 only.

- Encrypted outbox: unsent messages are kept in the vault (default ON on the phone, a switch in Settings), so they survive the OS killing the app and can be written offline. Costs are stated in the app and in `docs/DELIVERY.md`.

## Known gaps (tracked, not hidden)
- **G1** text fields keep their content in a Kotlin `String` (cannot be wiped). `SecureField` is the single place to replace with an input
  view that feeds IME text straight into the core's zeroizing buffers. Messages shown on screen also live in the JVM heap.
- The APK contains one tiny native library (`libandroidx.graphics.path.so`, from Compose). On GrapheneOS apps with native code get
  hardened_malloc and memory tagging; not tested on a device.
- Not run on a device or emulator (none available where this was built). What IS run: the Rust core's tests, the same Kotlin code against the real core over JNI on a Linux JVM, and the APK build with its packaging checks.
- **Tor is untested on a device:** build it first (`ANDROID_HOME=~/android-sdk scripts/build-tor-android.sh arm64-v8a` and `x86_64`, needs network once, sources are sha256-pinned), then `assembleDebug`. Tor's runtime directory lives in the app's private storage (`files/../tor`, removed when tor ends). Open: guard persistence, foreground service, the phantom-process limit (a child process may be killed), signature check of the tor tarball.
- **Photos (in progress, see docs/FILE_SHARING.md, "On the phone"):** pictures are sent as a re-encoded JPEG (long edge 1600 px, no metadata) and arrive as an offer the user accepts, then View / Save. EVERYTHING that parses a picture runs in an `isolatedProcess` service (`CleanerService`: no permissions, no network, no app files, a fresh process per job), never in the process that holds the keys: the core's cleaner hook (`strip::set_cleaner`) calls out to it, and when it is missing or fails the file is REFUSED (no in-process fallback). Photos are never queued, never stored and never in a backup. Not run on a real phone or over real Tor yet.
- No auto-lock on leaving the app, no foreground service, no notifications: they come with the Tor integration.
- Contact ids are positions in the list (the core addresses contacts that way): they shift when a contact is deleted (deleting is not in the UI yet).
