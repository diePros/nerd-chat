# Pairing over Tor — protocol and integration spec (GUI plan, phase 3)

Status: DRAFT for the adversarial spec review (docs/superpowers/specs/2026-11-09-gui-design.md section 9). Nothing is built.

## 1. Goal
Two people who are in the same room or far apart, whose devices share NO network, add each other with one short code told in person
or by phone and one link sent over ANY channel. The result is the same as today's same-network pairing: both sides get the other's
contact, `code-authenticated` trust (when the code was exchanged in person), and the safety number.

## 2. What is reused unchanged
`crates/exchange/src/pair.rs`: the pairing protocol itself (asymmetric SPAKE2 over a 10-digit code, key-confirmation tags, bundles
under an AEAD, proof of possession, a Noise/ML-KEM session handshake, transcript confirmation). It runs over any `PairStream`
(a byte stream with timeouts). A `PairingOffer` is consumed by exactly ONE attempt, expires, has no constructor from digits, and
failures feed a process-wide backoff (`Lockout`). Nothing in this protocol changes. Pairing over Tor only changes **how the two
streams come into existence**.

## 3. New pieces
### 3.1 The pairing service (offer side, role A)
- The offering device asks its Tor (through the transport) for an **ephemeral v3 onion service with NO client authorization**, random
  key, one virtual port, forwarding to a private local listener (a unix socket in our private directory in spawn mode; loopback TCP
  filtered by `check_tcp_client` in external mode: exactly as the contact services do today).
- **Why no client authorization:** the joiner has no key yet; the secret is the code, which SPAKE2 proves. This is the ONE place
  where the project hosts a public onion service, so it gets its own explicit API (`Tor::host_pairing`) next to the existing guard
  that refuses `ADD_ONION` without client authorization (`control.rs:add_onion`): that guard stays for every other call.
- The service is **not Detached** (it dies with our control connection), is removed (`DEL_ONION`) as soon as the first connection
  was accepted (success or failure), when the offer expires, when the user cancels, on panic, and on `Drop`. Its secret key and the
  listener are wiped/unlinked at the same moments.
- Exactly ONE inbound connection is accepted; a second connection attempt is closed unread. The accepted stream goes to
  `PairingOffer::accept` with the usual deadline.
- **Link** = the onion service id (56 base32 characters) wrapped as `nerdchat:pair/<id>`. It is public information, safe to send
  over any channel: whoever has it can only burn the single attempt (denial of service), not succeed without the code.
- **Code** = the existing 10 digits (`4821-7390`), told in person or by phone. Link and code must travel over **different**
  channels; the UI says so. A party who sees both can win the one guess (and this is the documented weakness, as in the same-network pairing).
- **TTL:** 10 minutes (the descriptor needs time to be published; the same-network offer keeps 5 minutes). One offer, one attempt.

### 3.2 The dial (join side, role B)
- The joiner enters the link and the code. The link is parsed strictly (`nerdchat:pair/` + 56 base32 characters, a valid v3 id
  checksum, nothing else), then the SOCKS5 CONNECT goes to `<id>.onion:<virtual port>` through the joiner's Tor with a **fresh
  stream-isolation token** per attempt. Retry with backoff for up to 3 minutes while Tor reports "descriptor unavailable" (the
  offer's service needs about 10-60 seconds to be reachable); stop at the first protocol-level answer, success or failure.
- After a connect, `PairingJoin::join` runs. A failed protocol run is NOT retried automatically (it consumed the offer).

### 3.3 Transport and engine integration
- `Transport` gets two methods: `host_pairing(&mut self, ttl) -> Result<PairHost, String>` (service id + a receiver for the single
  accepted stream + a handle that tears everything down) and `dial_pairing(&self, id: &str, isolation: &[u8; 16]) -> Result<BoxStream, String>`.
  The in-memory `MemTransport` implements both for tests (a map from id to channel); `TorTransport` implements them with the new `Tor` calls.
- The engine thread owns the transport (and the control connection), so hosting is a command to the engine (`Engine::pair_host(ttl)`,
  reply by channel); dialing needs only the cloned `DialFn` family (like contact dials) and runs on the app's pairing worker thread.
- `App` gets a pairing mode "over the internet" next to the LAN mode: same screens and the same sticky pairing state (`pair_rx`,
  `pair_ctl`, `pending_pair`, `pair_adv`), one pairing at a time. It requires the engine to be online (Tor ready); the GUI connects
  automatically, the terminal version tells the user to press `o` first.
- The hosting capability bit (`can_host`) decides who can offer: a device whose Tor refuses `ADD_ONION` cannot offer; the screen
  then says so and asks the OTHER person to offer. (The existing automatic probe at export/pairing time is reused to know this before the user starts.)

## 4. Security properties to hold (reviewer: attack these)
1. A passive observer of the link learns nothing that lets them pair (they lack the code); an observer of Tor traffic learns only what Tor already leaks.
2. An active party holding the link but not the code gets AT MOST the one attempt of the offer (burning it), never two guesses against one offer; failure lockout (`Lockout`) applies.
3. The pairing service exists only while an offer is open; no descriptor outlives it by design (a descriptor may linger in HSDir caches for a short time; documented).
4. Nothing about the contact keys is exposed before SPAKE2 completes: the service accepts a raw stream and the first bytes are the SPAKE2 message; no banner, no error text leaks whether an offer exists.
5. A joiner that dials a malicious link reaches only a service that must pass SPAKE2 with the user's code: the joiner reveals nothing before the protocol proves the code (as in the same-network join).
6. Stream isolation: a pairing dial never shares a circuit with contact traffic.
7. Resource use: one service, one accepted connection, bounded retries, bounded time; panic wipes the offer, the service key, the listener and the pairing buffers (like the existing pairing state).
8. External-tor trust: the same owner check and `--tor-trust-control` rules as for contact services apply to the control connection and to the loopback target.
9. A pairing link carries no information about the user's identity keys or contact names.

## 5. Non-goals
Short link aliases or a rendezvous server (no server of any kind), QR codes (no camera), automatic discovery, multi-party pairing, resuming an expired offer, and anything that keeps the pairing service alive after use.

## 6. Test plan
- Unit/in-memory: offer → join over `MemTransport` through the real `App` screens (both directions); expired offer; second connection refused; wrong code (one attempt consumed, lockout); cancel and panic tear the service down (`is_hosted` false); link parser accepts exactly valid ids; an offer cannot start while offline or while a pairing waits for P.
- Tor module with a scripted control port: `host_pairing` sends `ADD_ONION` WITHOUT `ClientAuth` only through this API (the guard still refuses everything else), removes it on every path, wipes the key.
- Live Tor test (`--ignored`): offer on one Tor, join from a second, full pairing, service gone afterwards.
- The existing same-network pairing tests keep passing unchanged.

## 7. Open points for the reviewer
Is 10 minutes right? Should the link carry a checksum beyond the onion id's own? Should the offer require `can_host` to have been probed (not guessed) before it starts? Is a public onion service for pairing an acceptable exposure compared to client-authorized services, given that the code gates everything?
