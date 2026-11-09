# Android port: assessment and integration flow (draft, based on branch `next`)

Priority decision for this port: **internet anonymity comes first; "store nothing" is negotiable.** Where the two conflict, the
rule below says which wins. Nothing here is built; section 1 is the only part that was verified by compiling.

## Decisions taken (2026-11-09)
- **Native Kotlin front end (Option B of 3.4).** Jetpack Compose, WhatsApp-style layout, clean but not minimal. Lives in `android/` (see `android/README.md`).
  It is the third native front end after the TUI and the Linux GUI. The egui GUI is not used on Android.
- **Releases:** no new distribution channel. The signed APK is meant to join the existing release flow (`scripts/release.sh`, SHA256SUMS): not wired yet.
- **Colours:** five palettes in one file (`Palettes.kt`) with a contrast test, switchable in Settings.
- **Built and verified:** `android/` builds a debug and a release APK, lints without errors, 11 unit/render tests pass. NOT verified: any run on a device.
- **Rust bridge built (2026-11-09):** `crates/android` (`nerd-chat-android`, a `cdylib`): a command layer over `nerd-chat-app` (the same idea as the Linux GUI's `Cmd`), a versioned JSON snapshot, and exactly two JNI exports (`nInit`, `nCall`). The only module that may contain `unsafe_code` is `ffi.rs` and it has no `unsafe` block (pinned by `tests/hygiene.rs`). It builds for `aarch64-linux-android` and `x86_64-linux-android` (NDK r29, 16 KB aligned, ~1.3 MB each), is packaged by Gradle, and is driven by Kotlin `RustBackend`.
- **Verified:** 10 + 2 Rust tests for the bridge (real vault, real core); the Kotlin side against the REAL library over JNI on a Linux JVM (create vault, refused short password, wrong password, persistence, non-BMP names, panic, purge); APK contents (JNI symbols exported, R8 keeps `NativeBridge`, no permissions). **Not verified:** anything on a phone or an emulator (no KVM in the build environment).
- **Needed in the existing code and done:** `statfs` type fix (`crates/net/src/tor/spawn.rs`), one read-only accessor `App::pairing_waiting()`. New dependencies: `jni 0.21.1` (+ `cesu8`, Windows-only helpers in the lock file); exemptions added to `supply-chain/config.toml` (`cargo vet`/`cargo deny` were NOT run: not installed in the build environment).
- **Superseded by the history file (2026-11-09, `docs/HISTORY_AND_TIMING_PLAN.md`): the outbox now lives in `<vault>.hist` and the setting is Persist (nothing/unsent/1 day/7 days), Android default 1 day; Keystore binding still to do.** Earlier outbox note:
- **Encrypted outbox done (2026-11-09):** unconfirmed texts are kept in the vault (on by default on the phone, switchable in Settings), survive a restart and can be typed offline. Core, engine, store format SBS6, bridge op `keep_outbox`, Kotlin settings toggle; tracker OB-1..OB-10.
- **Decided 2026-11-09 (plan only, not built):** on Android messages are kept by default (1 day, saved ones indefinitely), on Linux it is a setting that is off by default; deletion via per-epoch Android Keystore keys; file-time cover via grid-gated I/O. See `docs/HISTORY_AND_TIMING_PLAN.md` (measured: ctime cannot be forged, rename-based writes leak birth time).
- **Embedded Tor built (2026-11-09):** `scripts/build-tor-android.sh` builds tor 0.4.9.16 + OpenSSL 3.5.9 (static) + libevent 2.1.12 (static) with the NDK as `libtor.so` (PIE, 16 KB aligned, needs only libc/libm/libdl/libz) for arm64-v8a and x86_64; sources are pinned by sha256 (the tor signature is NOT yet checked). `useLegacyPackaging` extracts it to the native library dir, `INTERNET` is declared, `TorCfg.runtime_base/allow_disk` put tor's runtime directory in the app's private storage. Run on the x86_64 emulator (2026-11-09, API 36 AOSP image): vault creation works, `libtor.so` runs as a child of the app and the screen reaches "Tor connected". NOT run on a real phone (arm64) yet.
- **Still open:** foreground service and network-change handling for tor, guard persistence, bridges, the isolated-process cleaner (files are off), the secure input path (gap G1), foreground service and auto-lock.
- **Found while testing (not caused by this work):** on `next`, `purge_spares_planted_links_and_files_that_replaced_ours` fails here every time: purge recognises "our" file by (device, inode), and on ext4 a file deleted and recreated right away often gets the SAME inode, so a user's replacement file can be shredded. Also failing in this container on plain `next`: the seccomp/sandbox tests (`sandbox/tests/kernel.rs::installing_without_no_new_privs_fails_closed`, the helper tests `tui|gui/tests/cleaner.rs`) and `a_failed_save_does_not_hide...` (it uses file permissions, which root ignores).

## 0. Rule changes this priority implies
| Today (desktop) | Android |
|---|---|
| tor state only in a RAM directory (`spawn.rs::private_dir` refuses disk) | **Persist tor's guard state** (see 3.2): fresh guards on every start is worse for anonymity than a file on encrypted storage |
| refuse to start with swap (`hardening::swap_problem`) | drop the refusal: Android always has zram. Warn only |
| messages and outbox in RAM only | unchanged by default; an encrypted outbox in the vault is an optional later step (a phone is killed by the OS far more often) |
| no notifications (GUI spec) | one generic foreground-service notification is unavoidable; it must reveal nothing |
| no Android, no web view (GUI spec section "not doing") | Android becomes in scope; the web-view ban stays |

## 1. What compiles today (verified)
`cargo check --locked --target aarch64-linux-android` on `next`:

| Crate | Result |
|---|---|
| core, vault, store, strip, sandbox | compile unchanged |
| net | **2 type errors**, `crates/net/src/tor/spawn.rs:44` (`statfs.f_type` is `u64` on Android, `i64` on Linux) |
| exchange, chat, app | blocked only by `net`. **With a one-line patch (`st.f_type as i64`) in a scratch copy, net, exchange, chat and app all compile** |
| gui | fails: eframe pulls `android-activity`, which needs the `native-activity` or `game-activity` feature. Expected: configuration, not code |

The `sandbox` crate "compiles" only because it is a stub off x86_64 (`ARCH = 0`); it provides no protection there.
Checked only: `cargo check`, not tests, not running anything, not on a device.

## 2. What the `next` branch changes for Android
- `crates/app` (the UI-agnostic core, `App::handle(Key)`) exists and compiles for Android. A mobile front end does not need to fork the logic.
- **Pairing over Tor** (`docs/superpowers/specs/2026-11-09-tor-pairing-spec.md`): link + 10-digit code over different channels. This is the
  mobile pairing path; the same-LAN `TcpStream` pairing hardly applies to phones.
- **Delivery confirmation and resend** (`docs/DELIVERY.md`): unconfirmed texts are held in RAM and resent on reconnect, ack delayed 1-5 s.
  Useful on flaky mobile links; lost if Android kills the process.
- The GUI (`crates/gui`, egui) is desktop-shaped: three panes, mouse/keyboard, `wayland`/`x11`/`clipboard` features, no AccessKit.

## 3. Work items, by risk to anonymity

### 3.1 Nothing may leave except through Tor (highest priority)
- Embedded tor with `SocksPort unix:` and `OnionTrafficOnly` (already in `torrc()`); the app opens no other sockets. No DNS, no WebView,
  no Google Play services, no crash reporter, no analytics, no FCM push (a push server is a metadata server).
- The app needs the `INTERNET` permission, and tor shares its uid. So the isolation of the network is **inside the app design**, not a permission.
- Network changes (Wi-Fi to LTE): tor circuits die. Handle `ConnectivityManager` callbacks and toggle `DisableNetwork`; never fall back to a direct connection.
- **Bridges** (obfs4/snowflake): `SpawnConfig::extra_torrc` can already carry `Bridge` lines; ship a pluggable-transport binary the same way as tor. Many mobile users need this.
- Device leaks to close: `allowBackup="false"` and empty `dataExtractionRules` (a backup would copy the vault), `FLAG_SECURE` (recents thumbnail, screenshots),
  `IME_FLAG_NO_PERSONALIZED_LEARNING` and password-type input for secrets, lock-screen notification visibility `SECRET` with generic text, clipboard marked sensitive.

### 3.2 Tor on Android
- Run the tor binary as `libtor.so` from `nativeLibraryDir` (`extractNativeLibs="true"`): Android 10+ blocks exec from app data.
- **Risk to test:** a plain child process may be killed by Android's phantom-process limit. Preferred: tor in a declared service process (`android:process=":tor"`)
  using tor's embedding API; the Tor Project's `tor-android` does this. Either way hide it behind a `TorLauncher` seam so `SpawnedTor` keeps its control/SOCKS unix sockets.
- Runtime directory: no tmpfs for apps. Use the app's private files dir (short package name: unix socket paths are limited to ~100 bytes, `MAX_SOCKET_PATH`).
- **Guard persistence:** keep tor's `state` file (entry guards) across runs. Recommended: store it as a blob inside the vault (encrypted by the vault password) and
  restore it into the runtime dir at start. Consensus cache stays non-persistent (it shows nothing but "Tor was used" and only speeds bootstrap).
- `sweep_stale` uses `/proc/<pid>`, which is restricted on Android; replace with a lock/marker scheme.
- Arti (Rust Tor) is the long-term alternative. The Tor Project builds its Android VPN on it, but onion-service hosting was not recommended for privacy-critical use when last
  documented, and the code is written against C tor's control protocol (`ADD_ONION`, `ONION_CLIENT_AUTH_ADD`). Treat it as a later second backend, not the first.
- External mode (use Orbot): the owner check reads `/proc/net/tcp*`, which Android 10+ blocks; would need `--tor-trust-control` semantics. Optional.

### 3.3 File cleaning sandbox
- `cleaner.rs` re-executes `/proc/self/exe`; on Android that is `app_process64`. The aarch64 seccomp filter is also missing, and a filter that
  forbids `mprotect` conflicts with GrapheneOS's hardened_malloc (inference, to be tested).
- Replace with an `isolatedProcess` service (no network, no files, SELinux-enforced). Reuse `strip::wire` unchanged over a socketpair/pipe.
  `--no-sandbox` must not exist on Android.

### 3.4 Front end
- **Option A: egui via android-activity.** One toolchain and the existing `view.rs`. Weak points: soft keyboard and IME composition (Chinese, Japanese, Korean, Hindi
  users are a large share of mobile users), no accessibility, and the "no egui TextEdit for secrets" rule needs a custom IME bridge anyway.
- **Option B (recommended): thin Kotlin shell over `nerd-chat-app`** through JNI. A custom input view feeds committed IME text into `Key::Char` and shows only dots;
  messages render from borrowed text. Needs the "command layer on top of keys" that `lib.rs` calls planned (taps are not keys).
  Cost: breaks the "single Rust binary, no IPC" principle (not the web-view ban); message text lands in the JVM heap.
- Either way: single-pane navigation instead of three panes, panic as a visible always-on control (kills the process, clears the task), startup order from `crates/app/src/lib.rs` kept.

### 3.5 Background and presence (an anonymity topic, not only battery)
- Foreground service with `specialUse` type, generic notification; battery-optimisation exemption requested explicitly.
- All of a user's onion services come up and go down together. A phone online 24/7 leaks nothing new but is a constant target; a phone online in short windows leaks a daily
  pattern to anyone who knows the onion address (contacts, or anyone a bundle leaked to). Offer both, default to "online only while the app is open".
- `engine` timing hardening (ack delay, keepalives) carries over; Android adds wake/doze jitter that should be documented, not hidden.

### 3.6 Build, release and GrapheneOS
- NDK build with `cargo-ndk` (aarch64 first, x86_64 for the emulator); 16 KB page alignment; add targets to `rust-toolchain.toml`; extend `cargo-deny`/`cargo-vet` for the new crates.
- Reproducible APK: pinned AGP/NDK, normalised zip timestamps, own signing key, verification instructions (the desktop `repro-check.sh` has no Android equivalent yet).
- Distribution outside Play: GitHub releases with checksums, F-Droid-style or Obtainium/Accrescent. GrapheneOS users sideload normally.
- **GrapheneOS expectations:** no Google dependency here; per-app Network and Storage-scope toggles fit; hardened_malloc and memory tagging apply to apps with native code
  and may expose latent memory bugs in vendored C (tor). The "Exploit Protection Compatibility Mode" is a per-app fallback but weakens hardening. Test on a Pixel with MTE.
  Verdict: should run, to be confirmed on a device.

## 4. Integration flow

```
 [P0 prep, no Android code]
   fix statfs type (spawn.rs:44)  ->  CI job: cargo check --target aarch64-linux-android for core..app
        |
        v
 [P1 transport spike]  (gate: a real onion round trip between a Pixel/GrapheneOS phone and a Linux desktop)
   tor as libtor.so / :tor service process  ->  TorLauncher seam in net
   runtime dir in app files dir  ->  guard state saved in vault, restored at start
   network-change handling (DisableNetwork)  ->  bridge lines + PT binary
        |
        v
 [P2 platform layer in `app`]
   cfg(android): drop swap refusal, vault path = app files dir (no XDG/HOME), no /proc probes
   isolated-process cleaner (Binder + strip::wire)  ->  retire /proc/self/exe path on Android
        |
        v
 [P3 front end]  decision A or B (3.4)
   command layer over Key  ->  single-pane navigation  ->  secure input path (IME -> zeroizing buffers)
   FLAG_SECURE, panic control, generic notification, backup off
        |
        v
 [P4 service and presence]
   foreground service, battery exemption, online-window setting, reconnect/resend behaviour on kill
        |
        v
 [P5 hardening and test]
   leak test (all traffic through tor: packet capture on a hotspot), GrapheneOS + stock Android matrix,
   MTE on/off, doze, network switch, process kill mid-pairing
   adversarial review of: panic/purge on Android, vault/guard-state handling, isolated cleaner
        |
        v
 [P6 release]
   reproducible APK, signing, checksums, docs (GETTING_STARTED for phone), SECURITY_TRACKER updates (RAM-only claims changed)
```

Gates: do not start P3 before P1 shows a working onion round trip on a real phone; do not release before the P5 leak test passes.

## 5. Open questions for the owner
1. Option A (egui) or B (Kotlin shell)?
2. Persist tor guard state inside the vault (recommended) or as a plain file in app storage?
3. Encrypted persistent outbox: wanted or not?
4. Bridges/pluggable transports in the first release or later?
5. Minimum Android version, and Pixel/GrapheneOS only or any device?
