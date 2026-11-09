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
