# GUI spike report (phase 0) — egui/eframe 0.37

Status: DONE 2026-11-09. The spike lives outside the repository (`~/Documents/Code/sine-loco-gui-spike`, throwaway, not committed here). Result: **GO for egui**, with the
conditions below. Method and numbers are listed so that they can be repeated.

## What was tested
1. **Zeroizing text field.** `egui::TextBuffer` can be implemented for our own type (3 required methods plus `type_id`). The spike's `SecretBuf` has a fixed capacity (4 KiB, never reallocates: a realloc would leave an unwiped old copy), overwrites removed bytes and zeroizes on drop. egui accepts it in a `TextEdit` without changes.
2. **Copies of typed text in process memory.** A 24-byte marker is typed (headless: injected events; and in a real window), then the process scans its own `/proc/self/mem` for the bytes.
   - Headless egui (no window, with a control run to subtract the harness's own copies): **7 extra copies while the text is in the field** (the field buffer, the event, layout caches, the text-edit state); **0 extra after select-all + delete and three frames**, and also after dropping the buffer.
   - Real eframe window (glow/OpenGL, X11): the scanner itself leaves a noise floor of 2–3 hits (its own read buffer); typed runs show 3–5 hits while the text is visible and the **same as the noise floor after the field was zeroized** (24 frames later). Resetting egui's data/fonts, or a zero-on-free global allocator, changed nothing measurable. **No lingering copy was detectable above the noise.**
   - Limits of this test: it sees only this process's writable memory. It cannot see the compositor's/X server's pixel buffers (any text on screen is in them: also true of the terminal emulator for the TUI), GPU memory, or what a screen reader receives.
3. **Accessibility (AccessKit).** egui 0.37 depends on AccessKit unconditionally in `egui`; `eframe` exposes it as a feature (`accesskit`, on by default). The accessibility tree is only built when an operating-system adapter asks for it, so the headless test could not exercise it. When a screen reader is active, the text of every widget goes to it through the system accessibility bus: a copy outside our control. **Under D14 (strict) the GUI is therefore built WITHOUT AccessKit.** This is the "drop screen-reader support" branch that D14 already named; it is a visible limitation and is documented (README, GUI help). Revisit if a safe way to exclude secret widgets appears.
4. **Clipboard.** `clipboard` is a separate `eframe`/`egui-winit` feature (default on). The build leaves it out; nothing is copied to or read from the system clipboard.
5. **Linking and libraries.** The release binary links only `libc`, `libm`, `libgcc_s`; windowing and OpenGL libraries (X11, Wayland, xkbcommon, GL/EGL) are loaded at run time with `dlopen`. So the GUI binary is a normal dynamically linked glibc program that needs those system libraries to be present (true on Ubuntu 26.04, expected on Tails/GNOME). Release size 17.6 MB unstripped.
6. **Rendering.** Works with the hardware path and with software rendering (`LIBGL_ALWAYS_SOFTWARE=1`, Mesa llvmpipe).
7. **Screenshots** of the app's own frame work through `Context::request_screenshot` (no desktop capture).

## Problems found
- **Native Wayland:** under an automated launch (no user interaction) the window rendered one frame and then stalled (no further frames). X11/XWayland works. To be investigated in phase 2 (likely compositor frame callbacks for an unmapped/unfocused window). Until fixed the GUI forces the X11 backend when `WAYLAND_DISPLAY` misbehaves, or documents it.
- **Missing glyphs:** the default fonts have no ⚠ ✓ ● symbols (rendered as boxes). The GUI draws icons as shapes or embeds a small icon font (licence check).
- **Context drop hangs** in the headless harness (irrelevant to the app; avoided by `forget`).

## Not tested (best effort, D12)
- **Tails**: needs a real Tails session (user). The spike binary (`target/release/window`) can be run there; expected needs: a graphical session, `libxkbcommon`, X11 or Wayland, and OpenGL (software Mesa is enough).
- Wayland-native input, IME, HiDPI.

## Decision
GO: egui/eframe 0.37 with features `default_fonts`, `glow`, `wayland`, `x11` (no `accesskit`, no `clipboard`, no `web_screen_reader`, no `system_fonts`), a custom zeroizing `TextBuffer` for every text field that holds a secret or a message, and the stop condition of D14 not triggered. The conditions: no screen-reader support (stated openly), text only in zeroizing buffers on our side, caches cleared on lock/panic/chat close, the process exits on panic.
