# Nerd-chat for Android (Kotlin, native)

The third native front end next to the terminal UI and the Linux GUI. Kotlin + Jetpack Compose, a WhatsApp-style layout (chat list,
bubbles, delivery marks, a coloured top bar) with the project's privacy rules kept: **no timestamps, no read receipts, no typing
indicators, no presence beyond "connected over Tor"** (docs/DELIVERY.md). Focus: anonymity on the network first.

> **Status: interface only.** The screens run on `FakeBackend` (demo contacts, any non-empty password unlocks, nothing is stored,
> nothing is sent). The bridge to the Rust core (`nerd-chat-app`) and the embedded Tor are NOT built yet: see `docs/ANDROID_PORT.md`.
> This build declares **no permissions at all**, so it cannot reach the network.

## Layout
| Module | What | Builds without the Android SDK |
|---|---|---|
| `model/` | data model, the `ChatBackend` contract, `FakeBackend`, **colour palettes** and their contrast tests | yes |
| `ui/` | all Compose screens as plain JVM Compose + a test that renders them to PNG | yes |
| `app/` | the Android app: `MainActivity` (FLAG_SECURE, no backup, sensitive clipboard), manifest, icon. It compiles the **same source files as `ui/`** against androidx Compose | no (needs `ANDROID_HOME`) |

Rule for `ui/src/main`: only APIs that exist in both JetBrains Compose (desktop) and androidx Compose. Platform things (back button,
clipboard, process exit) are passed in by the host. The desktop compile therefore proves the Android sources too.

## Build and test
```bash
cd android
./gradlew :model:test :ui:test                 # 11 tests; writes screenshots to ui/build/shots/
ANDROID_HOME=~/android-sdk ./gradlew :app:assembleDebug     # app/build/outputs/apk/debug/app-debug.apk
ANDROID_HOME=~/android-sdk ./gradlew :app:assembleRelease   # unsigned; sign with NERDCHAT_KEYSTORE* (see app/build.gradle.kts)
```
Toolchain (verified 2026-11-09): Gradle 9.9.0 (wrapper), AGP 9.5.1, Kotlin 2.4.21, Compose BOM 2026.09.00 / Compose Multiplatform 1.12.2,
compileSdk 37 (SDK platform `android-37.0`), minSdk 29, targetSdk 36, JDK 21.

## Changing the colours
All palettes are in **`model/src/main/kotlin/app/nerdchat/model/Palettes.kt`**: one block per palette, light and dark scheme, plain hex.
Edit a value, run `./gradlew :model:test`: `PaletteContrastTest` fails if any text/background pair drops below WCAG AA (4.5:1) or a
bubble disappears into the conversation background. Add a palette = add a block and list it in `Palettes.all`. The user picks one in
Settings (stored as an id in a plain preference: it is only a colour). Palettes: Fern (default), Onion, Midnight, Graphite, Dusk.
Look at `design/*.png` (rendered from the real screens).

## What is deliberately in place already
No `INTERNET` permission (yet) · `allowBackup=false` and empty backup/transfer rules · `FLAG_SECURE` (no screenshots, blank recents
thumbnail) · clipboard copies marked sensitive · no analytics, no push, no Google services · launcher icon independent of the palette ·
arm64-v8a + x86_64 only.

## Known gaps (tracked, not hidden)
- **G1** text fields keep their content in a Kotlin `String` (cannot be wiped). `SecureField` is the single place to replace with an input
  view that feeds IME text straight into the core's zeroizing buffers. Messages shown on screen also live in the JVM heap.
- The APK contains one tiny native library (`libandroidx.graphics.path.so`, from Compose). On GrapheneOS apps with native code get
  hardened_malloc and memory tagging; not tested on a device.
- Not run on a device or emulator (none available where this was built): the APK is built, linted and unit-tested only.
- No auto-lock on leaving the app, no foreground service, no notifications: they come with the Tor integration.
