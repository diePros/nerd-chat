# Security policy

This project is **not audited**. Please read `docs/SECURITY_TRACKER.md` first: it lists every finding of our own reviews, what was fixed
and what is still open, so you do not need to report known items.

## Reporting a vulnerability
Please report privately, not in a public issue: use GitHub's **"Report a vulnerability"** (Security tab of the repository, private
vulnerability reporting). Include the commit hash, what you did, what you expected and what happened. Do not include real keys or
real contact data. We aim to acknowledge within 7 days and to fix or document the issue before publishing details.

## What is in scope
The cryptography and protocol (`crates/core`, `crates/exchange`), the vault (`crates/vault`, `crates/store`), the Tor transport
(`crates/net`, `crates/chat`), the file cleaner and its sandbox (`crates/strip`, `crates/sandbox`, `crates/app/src/cleaner.rs`),
the UI's handling of keys, prompts, the panic key and the privacy screen (`crates/app`, `crates/tui`), and the build (`scripts/`, `Cargo.lock`, `vendor/`).
Particularly interesting: anything that makes the app write plaintext or keys to disk, leak when you are online, accept an
unauthenticated peer or file, survive the panic key, or escape the cleaning helper's sandbox.

## Not in scope
Compromise of the device or of the terminal emulator, physical RAM attacks, a global passive observer of Tor, and social engineering of the user.
Weaknesses of upstream dependencies should be reported upstream (tell us as well so we can pin or patch).
