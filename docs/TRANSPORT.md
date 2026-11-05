# Transport: Tor in two modes (same code path above the Tor handle)

Per contact there are two onion services, one hosted by each side. A hosts `a.onion` for B; B dials it. Each onion
service REQUIRES v3 client authorization: only the contact whose auth key is in our bundle can CONNECT (the part of the
descriptor with the introduction points is encrypted to the authorized client keys). Onion identity and auth keys are
separate per-contact keys (the Ed25519 signing key never leaves Seburity). Both addresses and auth keys are inside the
signed bundle, so the safety number covers them.

**What client authorization does NOT do (review 5):** it does not hide that the service exists. Anyone who learns the
onion address can derive the blinded key, fetch the (outer-encrypted) descriptor from the HSDirs and so see WHEN the
service is online, for as long as that address exists. Therefore **a bundle is not public**: treat bundle files,
QR codes and pairing transcripts as confidential, deliver them over channels you would trust with "who I talk to", and
delete them after import. Rotating per-contact onion/auth keys over the authenticated channel is planned (tracker R5-M4).
All of a user's per-contact services also come online and go offline together (one tor), which a network observer of
descriptor uploads can correlate; Tor's own protections apply, nothing here adds to them.

## The two modes
| | EXTERNAL (Tails, Whonix, system tor, Tor Browser's tor) | SPAWN (any machine with a `tor` binary) |
|---|---|---|
| Who runs tor | the system | Seburity starts it in a private RAM dir, kills it on exit |
| Host onion service | via the system tor's CONTROL port (`ADD_ONION`) — needs control access | same, over a unix socket in a 0700 dir |
| Dial a contact | via the system tor's SOCKS port (works even with NO control access) | same |
| Config/bridges | whatever the system uses (Tails manages bridges itself) | `--tor-bridge` lines (planned flag) go into our torrc |
| Persistence | none: ephemeral onion services vanish when our control connection closes | none: RAM dir removed on drop |

What changes for Tails specifically:
1. **Never start a second tor there.** Tails' firewall only lets its own tor reach the Internet; a second tor would just fail.
   Use EXTERNAL mode, which reuses the system tor (and therefore Tails' bridge/obfuscation settings).
2. **Hosting needs the control port.** Whether the `amnesia` user may use it (and whether `ADD_ONION` is allowed) is NOT in
   Tails' public design docs (checked), so it must be tested on a real Tails: `seburity --probe-tor --probe-onion`.
   If hosting is refused, you can still dial contacts who host; both sides on such systems can't chat unless one side can host.
3. Tails' firewall treats LAN/loopback as open per its design page, so the local pairing link (l / c) is expected to work
   between two LAN machines. Untested.
4. Persistence: put the vault in Tails' Persistent Storage; keep the keyfile/counter on a separate stick.

## Who may we talk secrets to? (External mode, review 5)
Hosting an onion service means sending tor the onion SECRET key; dialing sends the client-auth SECRET. SAFECOOKIE does not
prove that the thing on the control socket is the tor you think it is (a local process squatting on 127.0.0.1:9051 can relay
to a real tor and pass the proof through). So before authenticating, Seburity checks the OS-level owner of the endpoint:
a unix socket's peer uid (SO_PEERCRED), or the uid of the LISTEN socket for a TCP port (/proc/net/tcp*). The owner must be
**you, root, or the owner of the system tor's cookie file** (`/run/tor/control.authcookie`). Otherwise nothing is sent and the
error says why. Cookie files are only read from that well-known location or from `--tor-cookie PATH`, never from a path
the control port announces. NULL and password authentication are subject to the same rule.

Two escape hatches, both explicit: `--tor-trust-control` ("I vouch for whoever owns this control port", e.g. a filtered
port on Tails/Whonix) and spawn mode (we created the sockets in our own 0700 directory, so they are ours by construction).
Residual risk you accept in External mode: **every program with control access to that tor** can read our client-auth
keys (`ONION_CLIENT_AUTH_VIEW`) and watch our onion traffic metadata (HS_DESC/STREAM events). Prefer spawn mode wherever the
network lets you run your own tor.

## Probe (run this on any machine, esp. Tails)
```
seburity --probe-tor                # passive: finds control/SOCKS ports, auth methods, cookie readability
seburity --probe-tor --probe-onion  # also creates + deletes ONE throwaway onion service (needs bootstrapped tor)
seburity --probe-tor --tor-control unix:/run/tor/control --tor-cookie /run/tor/control.authcookie
seburity --probe-tor --probe-onion --tor-trust-control   # you vouch for the control port's owner (Tails/Whonix filtered ports)
```
The report states for every control port whether its owner check passed (`owner check: ... TRUSTED / NOT TRUSTED`) and why.

## Security properties implemented in `net::tor`
- Control replies parsed strictly at byte level (size caps, mixed-code rejection, data blocks, control characters
  refused so a fake port cannot drive your terminal); every command argument validated so a stray newline can never
  smuggle a second control command; after any I/O error the connection is discarded (no stale replies).
- SAFECOOKIE only: the control port must PROVE it knows the cookie before we answer (a fake control port is detected);
  legacy COOKIE (no server proof) is refused. The cookie path comes from the peer, so it must be an absolute path to a
  regular, non-symlink file of exactly 32 bytes.
- `ADD_ONION` always with `Flags=V3Auth` + `ClientAuthV3`, never `Detach`; hardened with `MaxStreams=16 PoWDefensesEnabled=1`
  (retried without those on older tors); returned ServiceID must equal the address we derived. Spawn mode forwards to a
  UNIX socket in a private directory instead of a TCP port. (Checked against a real tor 0.4.9.11.)
- SOCKS5: hostnames go to tor unresolved, per-contact isolation credentials, Tor's extended error codes mapped to
  readable causes (peer offline / peer hasn't authorized you / unreachable).
- SPAWN: unix sockets only (no TCP listeners), 0700 RAM directory (tmpfs/ramfs verified), `__OwningControllerProcess`,
  torrc validated, empty `--defaults-torrc`, cleared environment, `PATH` lookup ignores relative entries, stale directories
  of dead processes are swept, `SocksPort ... ExtendedErrors OnionTrafficOnly` (readable onion errors, no clearnet dials).

## Chat engine (crate `seburity-chat`)
- **One connection per pair.** For each contact the party whose Ed25519 signing key is smaller DIALS, the other LISTENS (hosts its
  onion service for that contact). Only listeners publish a service, so you are not visible online for contacts that never dial you.
  A new, AUTHENTICATED inbound connection replaces a stale one (strangers fail the handshake and cannot).
- **Roles come from the bundles (decided: capability bit + explicit opt-in, no timers).** Every bundle (v4, `SBC4`) carries a
  SIGNED `can_host` bit, set by `--cannot-host` (use it when `--probe-tor --probe-onion` shows that your Tor refuses to host,
  e.g. a Tails with a restricted control port). The bit WE advertise to a contact is fixed at the first export/pairing with that contact and stored in the vault: roles always use what we told them, whatever flags we run with later. If exactly ONE side can host, that side hosts and the other dials; if both or
  neither can, the smaller signing key dials. Nobody publishes a service just to find out, and nothing is published after a number
  of failed dials any more. The bit is not part of the safety number (it is operational; both sides must compute the same number
  from key material).
- **Safety nets.** (1) A designated host whose hosting fails anyway (the bit was wrong, or a transient error) flips to dialing and says
  so. (2) `h` on a contact = "host anyway": YOU choose to host for a contact you would only dial (their bundle claims it can host
  but its Tor refuses). It is saved in the vault and costs presence privacy (below). (3) If neither side can host, both get a clear
  notice and nothing connects.
> **Privacy of hosting.** While you host for a contact, anyone holding THEIR copy of your bundle can see when you are online (even
> if they are offline). Therefore: you host only where the roles require it. A contact whose bundle says "cannot host" makes you host
> for them: that is inherent (otherwise no connection is possible), it is shown in the contact's details ("contact CANNOT host"),
> and a malicious contact can use it to learn when you are online: do not mark someone who must not see your presence as a contact.
> `host anyway` is OFF by default and the UI warns when you switch it on.
- **Handshake availability (review 6):** NO per-contact refusal before authentication (a token bucket let anyone who could connect
  lock the real peer out). Per hosted service only a replay cache runs before the handshake; CPU is bounded by ONE engine-wide budget
  (50 handshakes/s, burst 100); every handshake has a TOTAL deadline (45 s) instead of per-read timeouts; at most 4 unauthenticated
  handshakes run per contact and when they are full the OLDEST is aborted, so a newcomer (maybe the real peer) always gets in.
- **Who can even reach our listener:** spawn mode = a unix socket in a 0700 directory (only us). External tor = a TCP port on
  127.0.0.1 that every local user could reach, so an inbound client is dropped unread unless its socket belongs to us, root or the tor
  account (checked via /proc/net/tcp), or you passed `--tor-trust-control`.
- **Nothing outlives a contact:** deleting a contact (or going offline, or exiting) removes its hosted onion service AND the client-auth
  credential we installed in tor (`ONION_CLIENT_AUTH_REMOVE`), and unlinks its socket file. A contact deleted or added while tor is
  still starting is reconciled when the engine becomes ready. A bundle that reuses another contact's onion address is refused.
- **Connection lifetime:** cells are polled in 200 ms ticks (partial cells buffered); a keepalive cell every 30 s when idle; no cell for
  100 s drops the connection; the dialer reconnects with jittered backoff 3 s -> 60 s.
- **Messages:** RAM only. Texts are chunked into signed+encrypted 1 KiB cells (max 32 KiB per message), reassembled in a fixed-capacity
  wiped buffer, and everything a peer sends is sanitised (control, format, bidi, invisible, private-use characters become '?', stacked
  combining marks are capped; same rules for contact names). Unknown message kinds are ignored (room for files later).
- **Timing metadata:** keepalives and reconnect attempts are visible patterns to a network observer of your Tor entry; constant-rate
  cover traffic is not implemented.

## Not done yet
Pairing over an onion, role negotiation, delivery markers, constant-rate cover traffic, embedded tor binary
(bundling a static tor into the single file), bridge flags, control password support, idle/cover traffic.
