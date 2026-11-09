# Delivery confirmation and resend (tracker R6-I3, review 24)

**Problem.** A text written into a connection that has already died (the contact quit, Tor dropped the circuit) was lost
silently: the sender had no way to know, and the line did not even say `(queued)`.

**Design.** Every text carries a random 8-byte id (made by `Engine::send`, which returns it). The sender keeps the text in RAM until
the contact confirms it, and sends every unconfirmed text again, oldest first, on every new connection.

| frame | body | meaning |
|---|---|---|
| `KIND_TEXT_ID_CONT` 0x32 / `KIND_TEXT_ID_FINAL` 0x33 | `kind \| id(8) \| payload` | a text with its id; EVERY chunk carries it |
| `KIND_MSG_ACK` 0x31 | `kind \| id(8) * k`, 1 <= k <= 64 | "my UI has these texts" |
| `KIND_CAPS` 0x34 | `kind \| flags`, bit 0 = "I understand id frames and will confirm them" | sent FIRST on every connection (extra bytes ignored) |

The id is inside the text frame, so a text of up to ~940 bytes is still ONE cell, exactly as before (an earlier draft sent the id as
its own cell; review 24 pointed out that this made messages recognisable by their cell count). Frames are fixed-size padded cells inside
the authenticated session; ids never leave the encrypted session. The length rules of these frames are frozen (a wrong length cuts the
connection); later changes use new kinds.

**Old peers (v0.1.0).** v0.1.0 ignores frame kinds it does not know, so id frames sent to it would silently VANISH. Therefore nothing is
written on a new connection until we know what the peer understands: a new peer announces itself first (`CAPS`), and a peer that has not
done so within `Timing::caps_wait` (5 s) is treated as old. An old peer gets the plain v0.1.0 text frames, no id and no confirmation; a text
written to it counts as done (`Event::Delivered`, "handed over"), is not kept, so the 50-text outbox can never fill up for lack of
confirmations and nothing is resent on a reconnect. Verified with the real v0.1.0 binary over Tor, both directions and a reconnect
(no loss, no duplicates). One consequence: for an old peer a text written just before its connection died may be lost (v0.1.0's own behaviour).

**Confirmation timing.** A confirmation is not an immediate reply: it waits a random 1-5 s (`Timing::ack_delay_*`), all pending ids go
out in ONE cell, and a due keepalive carries it instead (it is traffic anyway), so an observer on the Tor path cannot time "a message
arrived" as a reply. The `(queued)` mark therefore stays a few seconds after a text arrives. Residual: the timing of a conversation
itself (who answers when) is untouched and is the standing C6-timing item.

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
- OPEN (not reachable from the TUI, whose draft is capped at 2 KiB): two sides that both resend ~50 x 32 KiB at once could block each
  other's writes until the 10 s write timeout, then repeat.
- The 500-line chat trim can drop an unconfirmed line from view; the warnings then undercount what the engine still holds.

Tests: `engine.rs` (resend with the same id, repeat handling with and without UI confirmation, `a_text_the_ui_never_saw_is_not_confirmed...`,
dead-connection resend, stale connection, full outbox, re-add, old-style peer, malformed frames), `proto.rs` (frames, one cell per
short text, id consistency), `app.rs` (confirmation by id, offline warning and marks, full outbox keeps the draft).

## Encrypted outbox (opt-in, key `O`; on by default in the Android app)
**Problem.** Unconfirmed texts live in the sender's RAM, so the OS killing the app (every phone does it) or closing the terminal loses them, and you cannot write
while offline. Session solves this with storage nodes run by strangers (`docs/COMPARISON_SESSION.md`, S1); we keep a stranger out of the loop and use the vault.

**What is stored.** Only texts the contact has NOT confirmed yet: per text `mid(8) | len | text`, per contact at most 50 (the engine's `MAX_UNCONFIRMED`; a test pins
the equality) and at most 1 MiB in the whole vault. No timestamp, no history, no received text, no confirmed text. A confirmed (or engine-refused) text is removed at once
and the vault is written ONCE per batch of confirmations. The choice itself (`on`/`off`) is stored in the vault and beats the front end's default.

**Order of operations.** Send: the text is written to the vault FIRST under the id the engine will use (`Engine::send_with_mid`); if the vault refuses (cap, write error) the
draft stays and nothing is sent. Start: `ContactCfg::with_outbox` seeds the engine's unconfirmed queue, so the texts go out in order on the first connection, exactly like texts queued while the contact was away, and are
confirmed under their own ids. Unlock: the kept texts show again as `(queued)` lines. Offline: with the outbox on you can still type; going offline neither warns nor marks anything
"not confirmed" for kept texts (a text that did not fit stays RAM-only and is still warned about). Switching it OFF removes the kept texts from the vault; switching it ON keeps what is already waiting.

**Format.** SBS6 (`vault flags` + a per-contact outbox) is written ONLY when the choice was made or an outbox is not empty; every other vault stays SBS5 and stays readable by older binaries.
SBS6 is a one-way upgrade (an older binary cannot open it).

**What it costs (honest).**
- The vault file now changes whenever you send or a message is confirmed: anyone who can look at your disk sees WHEN you wrote, not what.
- A deleted text may still sit in an old copy of the vault (flash wear levelling, backups, a copied file) until that copy is overwritten; it stays encrypted under the vault key.
- After a restart the receiver's list of already-seen ids is gone: a text it already showed, whose confirmation was lost, can appear twice. A duplicate was chosen over a loss.
- An older vault copy brought back would resend texts already delivered; the rollback counter exists to catch exactly that.

