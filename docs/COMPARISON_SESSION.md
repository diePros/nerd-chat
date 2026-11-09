# Comparison with Session (ideas to learn from)

Session (getsession.org, run by the Session Technology Foundation) is the reference point for this document: an open-source messenger that
also wants people to leave the big platforms, without phone numbers, and with a strong stance on metadata. It is NOT a copy target.
Its goal is "a Signal-like experience on a decentralised network"; ours is "per-contact unlinkability over Tor, no server, nothing stored
unless you say so". Where the two goals differ, ours wins; where Session found a good answer to a problem we also have, we say so.

## How reliable this is (read first)
- **Not read from the primary documents.** `getsession.org`, `docs.getsession.org` and `arxiv.org` (the whitepaper) could not be opened from the
  session this was written in (hosts not on its network allow-list). Everything about Session below comes from search-result summaries and
  third-party coverage (Privacy Guides, CyberInsider, Quarkslab's audit blog, PoPETs 2024, Session's support pages as quoted). Items marked
  **(unverified)** disagree between sources or rest on one source. Section 7 lists what to confirm from the primary documents.
- Session is a moving target: it announced "Protocol V2" in December 2025 as a proposal and posted an update in October 2026 (title only seen).
  Third-party pages that still describe the Oxen blockchain are out of date: the move to the "Session Network" was reported complete on 21 May 2025.
- We did not read Session's source code. Check its licence before doing so (it is a different licence family from our AGPL); we take ideas only, never code.

## 1. Side by side
| Topic | Session (as far as we could establish) | nerd-chat |
|---|---|---|
| Network | its own onion routing ("onion requests"): the client picks **3 random service nodes** (paid, token-staked) and wraps the request in 3 layers; each hop knows only its neighbours | **Tor** v3 onion services; one hosted per contact, with client authorisation |
| Offline delivery | **yes**: messages are stored on a *swarm* of service nodes (said to be 5-10, chosen deterministically from the recipient ID) until a time-to-live; docs say **2 weeks by default**, the 2020 whitepaper said a 96 h maximum **(unverified which is current)** | **no**: online-only peer to peer; unconfirmed texts wait in the sender's RAM (max 50) and are resent on every new connection |
| Identity | one long-lived **Session / Account ID** per user (public key, 66 hex characters), shown and shared | **no global ID**: a fresh key pair and onion service **per contact** |
| Encryption | Session Protocol (libsodium-style sealed messages, signed). **No forward secrecy** since 2021 (dropped after multi-device sync problems). Announced **V2**: rotating per-device keys, a shared per-account key, **ML-KEM** post-quantum KEM; "not finalised" as of the announcement | Noise `KKpsk0+psk2` with X25519 + **ML-KEM-768 hybrid**; ephemeral keys per connection (forward secrecy per connection); every message signed and encrypted; fixed 1 KiB cells |
| Metadata the network sees | the swarm sees the **recipient ID, timing and size** of stored messages; the sender's IP is hidden by the onion path | Tor relays see what Tor shows; contacts who know an onion address can see **when we are online** (documented, mitigated by key rotation) |
| Groups | closed groups (sender keys; "Groups v2" in 2025), public *communities* on community servers (SOGS) with **blinded IDs** | none (non-goal) |
| Unknown senders | message requests inbox; blinded IDs introduced because open-group IDs were harvested for spam | not needed: only a paired contact can even connect (client authorisation) |
| Multi-device | linked devices via config sync | none: one vault, one device |
| Push / notifications | Android: **fast mode** (Google FCM through a foundation-run server, registration over onion requests, tokens and timing exposed to Google) or **slow mode** (polling the swarm, more battery) | none: a foreground service, no push service |
| Message lifetime | disappearing messages | RAM only; keeping a message is a manual act (saved to the vault) |
| Spam control | proof of work on stored messages (whitepaper) **(unverified if still used)**, message requests | client authorisation; handshake rate limits and a replay cache before authentication |
| Governance / funding | foundation since Oct 2024; network and token changed twice (Loki, Oxen, Session Network 2025); a mandatory node upgrade in June 2026; funding appeals | one owner; unaudited |
| Independent audit | Quarkslab (2020-21, commissioned by Oxen; important findings patched; one disagreement on key generation); a 2025 critique of key generation was disputed by Session | none yet |

## 2. Where Session is ahead (for ordinary users)
1. **Offline delivery.** A phone is rarely online at the same time as its contact. Session's swarms make that invisible; for us it is the largest usability gap on mobile.
2. **Account continuity.** A recovery phrase restores an identity on a new phone; we have no story yet for "my phone broke".
3. **Disappearing messages and message requests** are familiar, finished features.
4. **Public scrutiny.** A published audit and a public back-and-forth with critics (including on key generation and on dropping forward secrecy) are what make a project checkable.

## 3. Where our design is ahead (for our priorities)
- **Unlinkability between contacts.** One global ID lets anyone who has it correlate you; our per-contact keys and onion services do not.
- **No third party stores anything.** In Session the swarm holds ciphertext addressed to your ID for weeks: recipient and timing are visible to those nodes.
- **Forward secrecy and post-quantum protection today**, not in a proposal.
- **A far larger, older anonymity network.** Session's onion path runs over a purpose-built, token-incentivised node set; Tor has years of adversarial research and many thousands of relays. (Whether Session uses persistent entry guards, we could not establish **(unverified)**: persistent guards matter for exactly the attack a small node set invites.)
- **No push token to link you.** The PoPETs 2024 study of 21 secure-messaging apps ("The Medium is the Message") found notification payload leaks through FCM; the token itself links a device to an account. We have no such token.

## 4. Ideas worth taking (ranked by value for the mobile, anonymity-first product)
| # | Idea | Session's version | Our version (keep our rules) | Effort | Notes |
|---|---|---|---|---|---|
| S1 | **Offline delivery without a stranger holding it** (**(a) DONE 2026-11-09**: the encrypted outbox, `docs/DELIVERY.md`; (b) open) | swarm of service nodes | (a) **encrypted outbox in the vault** (resend on reconnect; survives the OS killing the app); later (b) an **optional self-hosted mailbox**: an onion service the user runs (home server, Raspberry Pi), client-authorised, that holds sealed ciphertext for ONE user | (a) small-medium, (b) large | (a) is already open in `docs/ANDROID_PORT.md`. (b) keeps the promise "no corporation, no stranger" and gives Session's convenience to people who can run one box. Never default to a shared mailbox: it would see recipient and timing |
| S2 | **Rekey inside a long connection** | V2 rotates keys on a schedule and deletes old ones | `snow` already has `rekey`; our session code never calls it, so one Tor stream that lives for days keeps one transport key. Rekey every N cells / hours (or reconnect with a fresh handshake) | small-medium | Needs a frame both sides apply at the same cell number; check nonce handling and the frozen wire rules (`crates/core/tests/frozen_labels.rs`). Gives post-compromise healing within a session |
| S3 | **Disappearing messages for what we DO keep** | per-conversation timers | an expiry for messages saved to the vault and for the encrypted outbox (per contact; default off for saved, on for outbox) | small | Only meaningful once S1(a) exists |
| S4 | **Move to a new phone** | recovery phrase | an **encrypted vault export/import** (vault + rollback counter, never the keyfile) with a clear warning about rollback (`counter`) | medium | Phone loss is the most common mobile accident. Must keep the rollback protection honest: an imported old copy is a rollback |
| S5 | **Say plainly what each background mode costs** | fast vs slow mode explained in support pages | our Android foreground-service mode and the "online only while the app is open" default, explained in Settings in the same plain way | small | Do **not** add FCM/push. A wake-up service would have to be told "wake X" and so learns who talks to whom and when |
| S6 | **Audit readiness and published reasoning** | Quarkslab report, public responses | an audit package: threat model, frozen wire formats, tracker, fuzz targets, plus a short "decisions we will not trade away" note (e.g. forward secrecy vs convenience) | medium | Session's loss of trust over dropping forward secrecy for multi-device is the cautionary tale: write the trade-off down before a feature request forces it |
| S7 | **If groups ever come: pairwise fan-out** | sender keys (no forward secrecy in the closed-group design, per third-party description **(unverified)**) | send each message to every member over its own pairwise session, small groups only | large | Keeps forward secrecy, fixed cells and per-contact unlinkability, at a bandwidth cost that is fine for a handful of people |
| S8 | **Reduce dependence on one network** | Session changed networks twice and needs mandatory node upgrades | keep **external Tor** and **bridges** first-class, hide the Tor launcher behind one interface so a second backend (Arti) can be tried | medium | Already in the Android plan (3.2): this comparison is the reason to keep it |

## 5. Ideas rejected (and why)
- **Their own network and token.** Smaller anonymity set, token economics, recurring migrations and funding risk. Tor is the better base for "internet anonymity first".
- **Third-party message storage by default** (swarms). Recipient and timing visible to storage nodes; contradicts "no stranger in the middle".
- **A single, public account ID.** Convenient, but it is the correlation handle our design exists to avoid.
- **Push through Google FCM.** Even with encrypted payloads the token and timing are exposed; the PoPETs 2024 paper documents the wider leak class.
- **Linked devices with a shared account key** (for now). Session's own history shows the pull this exerts on forward secrecy. Revisit only with per-device keys and a written decision (S6).
- **Paid tiers / larger groups as a product line.** Out of scope.

## 6. Open questions this raises for us
1. Is S1(a) enough for mobile, or is the self-hosted mailbox (S1(b)) needed for the first release? (Depends on how long phones are offline in practice.)
2. Should a rekey (S2) be a new frame kind (frozen wire rules say later changes use new kinds) or a periodic reconnect?
3. How long may a saved message live by default (S3)? Today it is forever until deleted.
4. Which of S1-S8 belong before the first external audit, and which after (the roadmap says the audited core is not rewritten during the audit).

## 7. To confirm from primary sources (needs `getsession.org`, `docs.getsession.org`, `arxiv.org` and Session's GitHub allowed)
- the current default and maximum message TTL (2 weeks vs 96 h) and whether proof of work still exists;
- whether onion paths use persistent guard nodes, and how the client chooses and refreshes its node pool;
- the exact V2 design (the December 2025 post and the October 2026 update): per-device key rotation, linked-device flow, what is deleted when;
- how Groups v2 handles member removal and key rotation;
- what Session's swarm learns per message (sender hidden? size? timing?) and what the docs call their own limits;
- Quarkslab's full report (findings and the one disagreement) and any later audit.

## Sources
- Session Protocol V2 announcement (coverage): [Privacy Guides, 3 Dec 2025](https://www.privacyguides.org/news/2025/12/03/session-messenger-adds-pfs-pqe-and-other-improvements/); Session's own post: https://getsession.org/session-protocol-v2 (not opened)
- Onion requests and message routing (docs, as returned by search): https://docs.getsession.org/session-network/session-protocol/onion-requests-and-message-routing (not opened)
- Whitepaper "Session: End-To-End Encrypted Conversations With Minimal Metadata Leakage": https://arxiv.org/pdf/2002.04609 (not opened)
- Audit: [Quarkslab, Audit of Session Secure Messaging Application](https://blog.quarkslab.com/audit-of-session-secure-messaging-application.html); Session's reply: https://getsession.org/blog/a-response-to-recent-claims-about-sessions-security-architecture (not opened)
- Network migration and foundation: [CyberInsider](https://cyberinsider.com/session-migrates-to-its-own-blockchain-network-for-better-control-and-security/); https://getsession.org/the-future-of-session (not opened)
- Push notifications: [PoPETs 2024, "The Medium is the Message"](https://petsymposium.org/popets/2024/popets-2024-0151.php); Session's support article on notification modes: https://sessionapp.zendesk.com/hc/en-us/articles/4439028541849 (as quoted by search)
- Blinded IDs and message requests: https://getsession.org/upgrading-open-groups, https://getsession.org/blog/message-requests-release (as quoted by search)
- A single-source report of a May 2026 supply-chain incident involving Session was found and **deliberately not used** (no corroboration).
