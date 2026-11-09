# Android
- paring weird in general
  - verification warning displayed often.
  - stuck after in person check
  - implementation of other pairing options:
    - file
    - local ip
    - QR code?
- cant remove contacts without purge
- not displaying notification badge in contact list
- tui instructions

# GUI
- tui instructions

# TUI
- errors and warnings stay on screen


---
## Status (Claude, after the network-change work)
**Fixed, tests pass; the UI parts compile but were NOT clicked through on the emulator:**
- *cant remove contacts without purge*: Android: contact details now has "Remove this contact" with a confirmation dialog (one bridge operation `delete_contact`: keys, conversation and history of that contact are deleted).
- *not displaying notification badge in contact list*: cause found: after leaving the app the core still thought the chat was OPEN, so messages that arrived meanwhile were counted as read. The lock now closes the chat pane (and drops a half-typed draft). Not seen working with a real message yet.
- *tui instructions* (Android and GUI): the core's status texts spoke in key presses ("Press v", "F12 = panic", "press Esc, then o"). `Config.keys` is false for the phone and the desktop GUI, which now get wording about the screen; the terminal is unchanged. A bridge test checks that no key wording reaches the phone's snapshot. Texts that live in the GUI's own code and screens that are not status lines were not audited.
- *errors and warnings stay on screen* (TUI): the status line now clears itself (notes after 8 s, errors after 20 s). Security alerts stay until acknowledged, and a status that begins with WARNING or ROLLBACK (and the rollback-counter warning) stays until replaced.
- *verification warning displayed often*: the red warning icon is gone from the contact list and the chat header; the "Not verified yet" banner in a chat is neutral and has "Later" (until the next start). The details screen still shows the status.

**Not fixed, need more information:**
- *stuck after in person check*: I could not find it by reading the code and have no repro. What exactly do you see (which side: the one that shows the link or the one that enters it; does the dialog stay, the screen freeze, or does the contact not appear)? Was the app locked or in the background when the pairing finished?
- *implementation of other pairing options* (file, local IP, QR): not built. On the phone only the over-Tor link+code pairing exists. File and local-IP pairing exist in the core and the terminal/desktop apps (e/i, l/c) but need Android screens; QR needs a camera permission and a scanner/encoder, so it is a bigger decision.

## One-sided pairing (reported: TUI + Android; Android thought it was paired, the TUI had no bundle, no way out)
Cause (known and documented in `crates/exchange/src/pair.rs`): the LAST message of a pairing is the offering side's confirmation, so if it is lost, the offering side has finished and the joining side has failed. The Android app then held a peer key for the contact and refused to pair it again ("already has a peer key"), and the phone had no way to delete a contact.
Fixed:
- the in-person question now has a THIRD answer, **Discard** (Android button, TUI/GUI prompt answer `x`): nothing is saved and the contact stays unpaired; the dialog tells you to look at the other device first;
- contact details: **Pair again** forgets the contact's keys, gives it FRESH keys of our own (the old half-pairing holds our old bundle and onion address) and goes straight to the pairing screen for that contact; name and conversation stay;
- **Remove this contact** (see above);
- the failure message on the side that failed now says what to do on the other one.
Not changed: the protocol still cannot make both sides finish atomically (two-generals problem); the TUI has no "pair again" key yet (delete the contact and add it again there).

## Pairing options on Android (built after the report above; bridge tests pass with two phones, UI checked in screenshots and on the emulator)
The Pair screen has four tabs. Every way ends in the same checks (the in-person question, the safety number); a one-sided pairing can be discarded or paired again.
1. **Show link / Enter link** (over Tor, as before) plus a **QR code** of link+code in one (behind a button, with a warning: show it only to the person next to you). The other phone scans it with ITS CAMERA APP (or any scanner): `sineloco:pair/<id>#<code>` opens Sine Loco on "Enter link", filled in; the user still types a name and presses Pair. There is no camera code and no camera permission in the app.
2. **Contact text** (the file way, no network): "Show my contact text" (copy, share sheet, save as a file) and "Add their contact text" (paste, or open a file with the system picker). Same checks as importing a contact file.
3. **Same network**: a direct TCP connection on a private network with an address and a 10-digit code (also as a QR: `sineloco:lan/<ip>:<port>#<code>`). It is NOT through Tor and the screen says so. The phone only listens on, and only connects to, private addresses (loopback, 10.x, 172.16-31.x, 192.168.x, link-local); a public address is refused with a reason.
Open: an in-app camera scanner (a deliberate omission: it would add a camera permission and a scanning library to a high-risk app), pairing over Bluetooth, the terminal/GUI scanning the phone's QR (they can type the link and code).
