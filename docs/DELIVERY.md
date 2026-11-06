# Delivery confirmation and resend (tracker R6-I3, review 24)

**Problem.** A text written into a connection that has already died (the contact quit, Tor dropped the circuit) was lost
silently: the sender had no way to know, and the line did not even say `(queued)`.

**Design.** Every text carries a random 8-byte id (made by `Engine::send`, which returns it). The sender keeps the text in RAM until
the contact confirms it, and sends every unconfirmed text again, oldest first, on every new connection.

| frame | body | meaning |
|---|---|---|
| `KIND_TEXT_ID_CONT` 0x32 / `KIND_TEXT_ID_FINAL` 0x33 | `kind \| id(8) \| payload` | a text with its id; EVERY chunk carries it |
| `KIND_MSG_ACK` 0x31 | `kind \| id(8) * k`, 1 <= k <= 64 | "my UI has these texts" |

The id is inside the text frame, so a text of up to ~940 bytes is still ONE cell, exactly as before (an earlier draft sent the id as
its own cell; review 24 pointed out that this made messages recognisable by their cell count). Frames are fixed-size padded cells inside
the authenticated session; ids never leave the encrypted session. The length rules of these frames are frozen (a wrong length cuts the
connection); later changes use new kinds.

**Sender** (`engine.rs`, `Rt::unacked`). A new text is appended to `unacked` and, if a connection is up, written. `Up` resends all of
`unacked` in order. `ConnEvent::Acked` removes each named entry (the `Zeroizing` text is wiped on drop) and emits
`Event::Delivered { id, mid }`; unknown ids are ignored. There is no retransmit timer: a dead connection ends through the existing write
error or idle timeout, and the resend follows the reconnect. At `MAX_UNCONFIRMED` (50) a NEW text is refused; EVERY refusal (full, empty,
too long, unknown contact) emits `Event::Unsent { id, mid }`. The TUI refuses before taking the draft, so nothing typed is lost.

**Receiver.** The engine hands a new text to the UI as `Event::Message { mid, .. }` and remembers `(mid, confirmed = false)`; the UI calls
`Engine::confirm(id, mid)` only AFTER the line is in its own state, and only then is the confirmation written. A UI that goes away without
reading its events (going offline, quitting) confirms nothing, so the sender keeps the text and resends it later. A repeat of an id the
UI has confirmed is shown no more and confirmed again at once (the first confirmation may have been lost); a repeat the UI has not
confirmed yet is ignored (its `confirm` is on the way). A text read on a replaced connection is dropped without confirmation. The last 256
ids are remembered (RAM only). A re-registration of the contact (key rotation, `h`) carries `unacked` and `seen` over, and an invalid
re-registration leaves them untouched.

**What the confirmation is not.** "The contact's UI has it", not "the contact read it": no read receipts, no typing indicators, no
timestamps.

**UI.** A line says `(queued)` from sending until the contact confirms THAT text (found by its id, so order, the 500-line trim and
refusals cannot mislead). `o` (going offline) asks first when lines are unconfirmed ("press o again"); lines that were unconfirmed when
the engine went away say `(NOT CONFIRMED)` (they may have arrived), never `(NOT SENT)`, which is reserved for texts the engine refused.
The quit guard counts unconfirmed lines too.

**Limits (accepted or open, see the tracker, review 24).**
- Everything is RAM only: unconfirmed texts are lost when the sender quits or goes offline (both warn first).
- A duplicate can appear if the receiver restarts AND the confirmation of that text was lost; a duplicate was chosen over a loss.
- OPEN: a peer on 0.1.0 never confirms (it ignores the new frames but shows the texts): with such a peer the 50-text outbox fills up and
  every reconnect resends it. Needs a per-connection capability signal; decision pending.
- OPEN: the confirmation is a cell sent right after the text is held: an observer on the Tor path can tell "message" from "keepalive" by
  that reply. The frame already carries up to 64 ids so confirmations can be delayed and batched; policy decision pending.
- OPEN (not reachable from the TUI, whose draft is capped at 2 KiB): two sides that both resend ~50 x 32 KiB at once could block each
  other's writes until the 10 s write timeout, then repeat.
- The 500-line chat trim can drop an unconfirmed line from view; the warnings then undercount what the engine still holds.

Tests: `engine.rs` (resend with the same id, repeat handling with and without UI confirmation, `a_text_the_ui_never_saw_is_not_confirmed...`,
dead-connection resend, stale connection, full outbox, re-add, old-style peer, malformed frames), `proto.rs` (frames, one cell per
short text, id consistency), `app.rs` (confirmation by id, offline warning and marks, full outbox keeps the draft).
