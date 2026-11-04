# Transport: Tor in two modes (same code path above the Tor handle)

Per contact there are two onion services, one hosted by each side. A hosts `a.onion` for B; B dials it. Each onion
service REQUIRES v3 client authorization: only the contact whose auth key is in our bundle can even fetch the
descriptor. Onion identity and auth keys are separate per-contact keys (the Ed25519 signing key never leaves
Seburity). Both addresses and auth keys are inside the signed bundle, so the safety number covers them.

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

## Probe (run this on any machine, esp. Tails)
```
seburity --probe-tor                # passive: finds control/SOCKS ports, auth methods, cookie readability
seburity --probe-tor --probe-onion  # also creates + deletes ONE throwaway onion service (needs bootstrapped tor)
seburity --probe-tor --tor-control unix:/run/tor/control --tor-cookie /run/tor/control.authcookie
```

## Security properties implemented in `net::tor`
- Control replies parsed strictly (size caps, mixed-code rejection, data blocks); every command argument validated so a
  stray newline can never smuggle a second control command.
- SAFECOOKIE only: the control port must PROVE it knows the cookie before we answer (a fake control port is detected);
  legacy COOKIE (no server proof) is refused. The cookie path comes from the peer, so it must be an absolute path to a
  regular, non-symlink file of exactly 32 bytes.
- `ADD_ONION` always with `Flags=V3Auth` + `ClientAuthV3`, never `Detach`; returned ServiceID must equal the address we derived.
- SOCKS5: hostnames go to tor unresolved, per-contact isolation credentials, Tor's extended error codes mapped to
  readable causes (peer offline / peer hasn't authorized you / unreachable).
- SPAWN: unix sockets only (no TCP listeners), 0700 RAM directory, `__OwningControllerProcess`, torrc validated, refuses
  to put tor state on disk unless explicitly allowed.

## Not done yet
Chat engine + TUI screens (host/dial loops, reconnects, offline queue in RAM), pairing over an onion, embedded tor binary
(bundling a static tor into the single file), bridge flags, control password support, idle/cover traffic.
