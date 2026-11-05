# Key rotation (tracker R5-M4)

**Problem.** A bundle contains the contact's onion address. Anyone who ever held a copy (the contact, a leaked file, a
copied QR) can derive the service's blinded key and see **when that service is online, for as long as it exists**
(client authorization hides the introduction points, not the existence). Rotation ends that for old copies.

**What rotates.** Only the *transport* keys of one contact relationship: our onion-service key and our client-authorization
key. The identity keys (Ed25519 signing, X25519, ML-KEM) never change, therefore **the safety number does not change**
(the fingerprint covers identity keys only; the capability bit and the transport keys are excluded).

**Start:** `K` on a contact while online. The new keys are generated, saved in the vault (`next_transport`) and the engine
hosts the NEW service next to the OLD one (if we host for that contact; a pure dialer needs no second service).

**Protocol** (all frames travel inside the authenticated, signed session; each carries 64 bytes: onion pub | auth pub):
1. `OFFER` — we propose our new keys (re-sent on EVERY new connection while pending, so a lost ack is harmless).
2. The contact validates (valid keys, not equal to the current ones, not reused by another contact, no second rotation
   while one is unfinished), saves "peer := new keys, peer_old := old keys" in its vault, answers `ACK`, and switches: it
   dials/authorizes the new keys; the old client key stays authorized on its hosted service until step 4.
3. On `ACK` we commit (new keys become THE keys, old secrets are zeroized), send `DONE`, and re-register the contact:
   the old onion service and its client-auth credential are removed from Tor.
4. `DONE` (or our current keys, announced on every later connection) tells the contact the rotation finished: it forgets
   `peer_old` and stops authorizing the old client key.

**Crash/loss safety.** Nothing is switched before the other side has saved its half. Until the ACK arrives we host both
services, so the contact reaches us whether or not it already switched; if the vault write fails on either side the step is
undone and no ack is sent.

**Limits (honest).**
- Anyone who copied our bundle *before* rotation learns nothing new afterwards, but could already have recorded when the old
  service was online up to then. Rotate regularly if that matters.
- The new bundle you export after rotation contains the new address; **old copies you gave to third parties stop working**.
- While a rotation is pending (until the contact ACKs: possibly never, e.g. an old binary or an absent contact) BOTH services are
  published, so the old address keeps leaking presence exactly as before. The UI refuses export meanwhile. There is no cancel (it would
  strand a contact that already switched) and, if the NEW service cannot be hosted in a later session, the contact that already
  switched cannot reach us until it can (open: dial fallback to the old address, retry of ADD_ONION).
- A hostile contact can only propose its own keys; it cannot make us rotate ours. We accept at most ONE rotation per contact per
  hour (each costs a vault write and a re-publish of our service), at most six rotate frames per connection, and a DONE never
  triggers a re-add. A contact that never sends `DONE` leaves `peer_old` (an extra authorized client key for *its own* old key) and
  blocks further rotations by THAT contact only; our own rotation is independent.
- Bundles are not versioned: an old signed copy of a contact's bundle re-imported later would still match the safety number
  (the transport keys are not part of it). Do not re-import old bundle files; open: a signed transport generation counter.
- The safety number of every existing contact changed when rotation was introduced (fingerprint v2); re-verify out of band.
- The peer's old (onion, auth) public keys are kept in the vault while `peer_old` is set (public data).
