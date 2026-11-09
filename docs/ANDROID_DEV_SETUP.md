# Android development setup (continue on your laptop)

Everything below was done and verified on 2026-11-09 in a Linux cloud container. Commands are for Linux/macOS; on Windows use WSL2 (the
Rust side already assumes Linux) or Android Studio's own SDK manager. What is NOT verified is flagged "untested".

## 1. Where the work is
| Thing | Where |
|---|---|
| Android app (Kotlin) | branch `claude/stoic-hopper-i5rqlk`, folder `android/` (commit `26f92f2`) |
| Assessment, plan, decisions | `docs/ANDROID_PORT.md` (same branch) |
| Rust core with the UI-agnostic `nerd-chat-app` crate and the Linux GUI | branch `next` (NOT merged into the branch above) |
| `main` | the old TUI-only state |

The Android branch was cut from `main`, so it does not contain `crates/app` or `crates/gui`. The first real integration step (the Rust bridge)
needs `next`: merge or rebase the Android branch onto `next` first (`git fetch origin && git checkout claude/stoic-hopper-i5rqlk && git merge origin/next`;
neither `android/` nor `docs/ANDROID_PORT.md` exists on `next`, so a conflict is unlikely).

```bash
git clone https://github.com/diePros/nerd-chat && cd nerd-chat
git checkout claude/stoic-hopper-i5rqlk
```

## 2. Tools you need
| Tool | Version used | Notes |
|---|---|---|
| JDK | 21 (Temurin/OpenJDK) | the build targets Java 17 bytecode; any JDK 17+ runs Gradle |
| Gradle | **9.9.0 via the wrapper** (`android/gradlew`) | do not use a system Gradle; AGP 9.5.1 refuses anything below 9.6 |
| Android SDK | platform `android-37.0`, build-tools `36.0.0` | see 3 |
| Rust | 1.98.1 (`rust-toolchain.toml`) | REQUIRED for the real app: the bridge library is built with cargo (`rustup` installs the Android targets from `rust-toolchain.toml` by itself) |
| Android NDK | r29, `29.0.14206865` | linker for the Rust library; install with `sdkmanager "ndk;29.0.14206865"` |
| Python 3 + Pillow | optional | only to recreate the contact sheets in `android/design/` |

Android Studio (current stable) can open `android/` directly and brings its own SDK manager; if you use it, install the same platform and
build-tools versions and skip step 3. Untested: opening the project in Android Studio (the build was only run from the command line).

## 3. Install the Android SDK from the command line
```bash
mkdir -p ~/android-sdk/cmdline-tools
# download "Command line tools only" for your OS from https://developer.android.com/studio#command-line-tools-only
unzip commandlinetools-*.zip -d /tmp/cmdtools && mv /tmp/cmdtools/cmdline-tools ~/android-sdk/cmdline-tools/latest
export ANDROID_HOME=$HOME/android-sdk
yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --sdk_root=$ANDROID_HOME --licenses   # YOU accept Google's licence here
$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --sdk_root=$ANDROID_HOME "platforms;android-37.0" "build-tools;36.0.0" "platform-tools" "ndk;29.0.14206865"
```
Put `export ANDROID_HOME=$HOME/android-sdk` in your shell profile (or create `android/local.properties` with `sdk.dir=/home/you/android-sdk`;
it is git-ignored). **Without either of them, `settings.gradle.kts` leaves out the `:app` module** on purpose, so `:model` and `:ui` still build and test.

## 4. Everyday commands (run in `android/`)
```bash
./gradlew :model:test :ui:test                       # 27 tests; screenshots land in ui/build/shots/
                                                     #   :model:test first builds the HOST bridge library with cargo and then runs the real JNI end-to-end test
                                                     #   (without cargo it is skipped; `-x buildBridgeHost` skips the build explicitly)
./gradlew :app:assembleDebug                         # app/build/outputs/apk/debug/app-debug.apk (~33 MB, debuggable); runs cargo for arm64-v8a and x86_64
./gradlew :app:assembleRelease                       # app/build/outputs/apk/release/app-release-unsigned.apk (~5 MB, R8-shrunk)
./gradlew :app:assembleDebug -Pdemo                  # in-memory demo backend instead of the Rust core
cargo test --workspace --locked                      # (repository root) the Rust side
./gradlew :app:lintDebug                             # report in app/build/reports/lint-results-debug.html (warnings only today)
```
The first run downloads Gradle 9.9.0, the plugins and about a gigabyte of dependencies. **If it fails with HTTP 429 from Maven Central, just rerun**
(it resumes from the cache); that happened repeatedly behind the cloud proxy and is unlikely on a normal connection.

### Install on a phone
```bash
# phone: Settings > About phone > tap "Build number" 7 times > Developer options > USB debugging on (GrapheneOS: same path)
$ANDROID_HOME/platform-tools/adb devices
$ANDROID_HOME/platform-tools/adb install -r app/build/outputs/apk/debug/app-debug.apk
```
Untested: nothing has been installed on a device or an emulator yet. First things to look at on a real phone: the lock screen, keyboard
behaviour in the message field (this is gap G1), light/dark switching, rotation (the activity handles config changes itself, state is kept),
the blank recent-apps thumbnail. The demo backend accepts any non-empty password and stores nothing.

### Signing a release (never commit keys)
```bash
keytool -genkeypair -v -keystore ~/nerdchat-release.jks -alias nerdchat -keyalg RSA -keysize 4096 -validity 10000
export NERDCHAT_KEYSTORE=$HOME/nerdchat-release.jks NERDCHAT_KEYSTORE_PASSWORD='...' NERDCHAT_KEY_ALIAS=nerdchat
./gradlew :app:assembleRelease      # now signed; verify: $ANDROID_HOME/build-tools/36.0.0/apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
```
Untested: the signed path (only the unsigned release build was run). Keep the keystore backed up offline: losing it means users cannot update.

## 5. How the project is wired (so you do not rediscover it)
- `model/` pure Kotlin JVM: data, `ChatBackend` interface, `FakeBackend`, palettes. `ui/` plain JVM Compose (JetBrains Compose Multiplatform 1.12.2, desktop artifacts)
  so screens compile and render PNGs without the Android SDK. `app/` the Android application.
- **`app/` compiles the same source files as `ui/`** (`sourceSets.getByName("main").kotlin.directories.add("../ui/src/main/kotlin")` in `app/build.gradle.kts`).
  Rule for `ui/src/main`: only APIs present in both toolkits; platform things (back button, clipboard, exit) are parameters of `NerdApp`.
- **Version coupling, learned the hard way:** current Compose (BOM 2026.09.00 = 1.12) needs compileSdk 37 and AGP 9.1+; AGP 9.5.1 needs Gradle 9.6+;
  AGP 9 has built-in Kotlin, so do NOT apply `org.jetbrains.kotlin.android`, and put extra Kotlin source dirs under `android { sourceSets ... kotlin.directories }`
  (the old `java.srcDir` and `kotlin { sourceSets }` forms silently do nothing or fail). Keep the desktop Compose Multiplatform version and the androidx BOM on the same minor (1.12.x).
- `settings.gradle.kts` always adds `google()` (needed for androidx and AGP) and includes `:app` only when an SDK is found.
- Screenshots: `ui/src/test/.../ShotsTest.kt` renders with Skia headlessly (`ImageComposeScene`, internal Compose API; it may need an `@OptIn` change after Compose updates).
- Change colours only in `model/.../Palettes.kt`; the contrast test guards them (`android/README.md`).

## 5b. Known test failures that are NOT yours (seen in the cloud container, identical on plain `next`)
`cargo test --workspace --no-fail-fast` reports failures in `sandbox/tests/kernel.rs::installing_without_no_new_privs_fails_closed`, `tui` and `gui` `tests/cleaner.rs`, and two tests of `nerd-chat-app`
(`a_failed_save_does_not_hide_that_the_vault_file_may_already_hold_the_message` needs a non-root user; `purge_spares_planted_links_and_files_that_replaced_ours` depends on inode reuse, see `docs/ANDROID_PORT.md`).
On your laptop as a normal user most of these may pass: if one still fails there, it is worth a look.

## 6. Where to continue (in this order)
1. Install the debug APK on a real phone (ideally a Pixel with GrapheneOS) and note what looks or feels wrong: that feedback is the cheapest next step.
2. DONE: `next` is merged and the Rust bridge exists (`crates/android`, `android/model/.../RustBackend.kt`). First thing to try on the phone: create a vault (the key derivation runs for real: a few seconds), add a contact, open Settings and see the honest "Tor could not start" message.
3. Embedded Tor per `docs/ANDROID_PORT.md` section 3.2 (this is the anonymity-critical part; gate: a real onion round trip phone to desktop). It needs: a `libtor.so` for arm64, `allow_disk`/runtime-directory support in `TorCfg` (Android has no tmpfs for apps), the `INTERNET` permission, then the foreground service and the isolated-process cleaner.
4. Replace `SecureField` (gap G1) with an input that never builds a Kotlin `String` for secrets.
5. Wire the APK into `scripts/release.sh` and its SHA256SUMS (no new channel), and decide the signing-key custody.

## 7. Cloud-session leftovers you do not need
The SDK in the cloud container (`~/android-sdk`), the Gradle caches and all build output are not in git and disappear with the container. Everything needed to rebuild is in the repository
plus the steps above.

## 8. State after the history work (2026-11-09)
Rust side and Kotlin UI/bridge use the `Persist` setting (nothing / unsent / 1 day / 7 days; Android default 1 day). Verified in the cloud container: all Rust and Gradle tests, debug/release assemble, lint.
**Written but never run on a device:** the Android Keystore implementation of `PlatformKeys` (`app/.../AndroidKeystoreKeys.kt`: one AES-256-GCM key per 24 h epoch, non-exportable, StrongBox when present, else TEE) and the erase job (`EraseJobService`, every ~6 h, also after a reboot, needs only the key names; the app also erases at every start). The Rust side calls the key store through JNI (`crates/android/src/keys.rs`, names and descriptors pinned by `PlatformKeysTest`). The JNI callback itself has no host test (history only writes once a contact is PAIRED and a message exists), so **the first thing to test on the phone is: pair, send a message, restart the app, see the message again.** If it is gone, the key store or the callback is broken (the app then shows the history as empty).
What strength to expect: StrongBox (Pixels, many recent phones) = deleting the key is a real erase in secure hardware; TEE-only = the key blob is deleted but the hardware root key remains, so a forensic copy of the blob might still open it (best effort). `AndroidKeystoreKeys.level` says which one a phone got (not shown in the UI yet).
A clock moved far into the future makes the erase job destroy younger keys too (history lost, nothing exposed).
Things to look at on the phone: whether the history file stays at a constant size and inode (`adb shell stat`), f2fs write behaviour, keyboard flags in the message field (R32-K1).
