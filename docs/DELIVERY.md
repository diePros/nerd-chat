# Delivery confirmation and resend (tracker R6-I3)

**Problem.** A text written into a connection that has already died (the contact quit, Tor dropped the circuit) was lost
silently: the sender had no way to know, and the line did not even say `(queued)`.

**Design.** Every text carries a random 8-byte id. The sender keeps the text in RAM until the contact confirms it, and sends
every unconfirmed text again, oldest first, on every new connection. Nothing else changes in the transport.

| frame | body | meaning |
|---|---|---|
| `KIND_MSG_ID` 0x30 | `kind \| id(8)` | sent right before the chunks of one text |
| `KIND_MSG_ACK` 0x31 | `kind \| id(8)` | "my app has this text", sent after the text was handed to the UI |

Both travel inside the normal authenticated, padded session cell: the network sees nothing new, only one more fixed-size cell per
text (and one per confirmation). Ids never leave the encrypted session.

**Sender** (`engine.rs`, `Rt::unacked`). A new text is appended to `unacked` and, if a connection is up, written. `Up` resends
all of `unacked` in order. `ConnEvent::Acked` removes the entry (the `Zeroizing` text is wiped on drop) and emits
`Event::Delivered`; unknown ids are ignored. There is no retransmit timer: a dead connection ends through the existing write error
or idle timeout, and the resend follows the reconnect. At `MAX_UNCONFIRMED` (50) unconfirmed texts a NEW text is refused
(`Event::Unsent` + notice) instead of dropping an older one; the TUI refuses before taking the draft, so nothing typed is lost.

**Receiver.** `Rt::seen` keeps the last 256 ids (RAM only). A text with a known id is not shown again but IS confirmed again (the
first confirmation may have been lost). A text arriving on a replaced connection is dropped without confirmation, so the sender
resends it on the current one. A re-registration of the contact (key rotation, `h`) carries `unacked` and `seen` over.

**What the confirmation is not.** It means "the contact's client has it", not "the contact read it": no read receipts, no typing
indicators, no timestamps. It reveals that the contact's client is running, which the established connection already shows.

**Limits (accepted).**
- Everything is RAM only: unconfirmed texts are lost when the sender quits (the quit guard counts them) or goes offline.
- A duplicate can appear if the receiver restarts AND the confirmation of that text was lost; a duplicate was chosen over a loss.
- Compatibility: a peer on 0.1.0 does not send ids or confirmations. Its texts still arrive; texts sent to it are shown again
  after every reconnect until the sender quits. Nobody ran 0.1.0 before this change.
- The UI maps `Event::Delivered` to the OLDEST unconfirmed line of that contact (texts are confirmed in sending order).

**UI.** A line says `(queued)` from sending until the contact's app confirms it, connected or not. The quit guard counts it as
unconfirmed.

Tests: `engine.rs` (`an_unconfirmed_text_is_resent_with_the_same_id_until_the_contact_confirms_it`,
`a_resent_text_is_shown_once_but_confirmed_every_time`, `a_text_written_to_a_dead_connection_arrives_after_the_reconnect`,
`a_peer_without_ids_still_delivers_and_a_malformed_confirmation_cuts_the_connection`, `a_full_outbox_refuses_the_new_text_and_keeps_the_old_ones`,
`unconfirmed_texts_survive_a_settings_change_of_the_contact`), `proto.rs`, `app.rs`.
