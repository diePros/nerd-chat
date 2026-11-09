# Project name: ideas, decision, how to change it

**Decision 2026-11-09: the project is now called `Sine Loco`** (kebab `sine-loco`, Android package `app.sineloco`). Latin "sine loco" = "without a place": the messages are stored nowhere. Chosen over Unkept, Nulla, Nought, SineChat and bare Sine (bare "Sine" is a registered US trademark of Sine Group Pty Ltd in class 9, visitor sign-in software; SineChat carries the same risk; Sine Loco had no hit in the Apple App Store, Google Play, F-Droid or the US register as far as web search could tell: NOT a legal clearance, EU/AU registers unchecked). "Tor" must not appear in the name (Tor Project trademark policy). The text below is the history. Before 2026-11-09 the working title was `nerd-chat` (also the GitHub repository name, chosen by the owner "for now"). Until 2026-11-06 the codename was
`seburity`. That codename still appears, on purpose, in the strings listed in `scripts/frozen-labels.txt` (disk/wire formats and
cryptographic domain separation: vault, contact bundles, messages, handshake, pairing, safety numbers). They must never change with the
name, or every existing vault and bundle would break; `crates/core/tests/frozen_labels.rs` guards this.

## Change the name in one step
```bash
git status --short                                  # must be clean
python3 scripts/rename-project.py NEW-NAME --dry-run   # list what would change
python3 scripts/rename-project.py NEW-NAME --test      # rename, refresh Cargo.lock, run the whole test suite
```
It renames the Cargo packages and `use` paths, the binary, the UI title, env-var prefixes, docs, scripts and policy files, and keeps the
frozen labels and `vendor/` untouched. The current name is stored in `scripts/project-name.txt`. Rename the GitHub repository by hand.
`git checkout . && git clean -fd` undoes a rename that has not been committed.

## Ideas (checked on 2026-11-06 against crates.io and GitHub; availability changes, check again before using one)
| Name | Meaning | crates.io / GitHub |
|---|---|---|
| **Symbolon** | Ancient Greek token broken in two: each friend keeps one half to recognise the other later = in-person key exchange | free / a few small unrelated repos |
| **Sub Rosa** | Latin "under the rose": in confidence | `subrosa`, `sub-rosa` free / one tiny unrelated messenger repo |
| **Undertone** | a quiet voice underneath | free / none found |
| Omertà | code of silence | free, but the mafia association fits badly |
| Tessera | the same split-token idea in Latin | taken |
| Sotto | "sotto voce", under the voice | taken |
| Allium | the onion genus (Tor) | taken, a messenger repo exists |
| Warren, Cairn, Hearth, Nightjar, Tacet, Shibboleth, Sigil, Murmuration | various | all taken on crates.io |
More themes to try: per-contact keys ("one key per door"), no server in between ("direct line"), panic wipe ("scorched earth", "tabula rasa"), Tor/onion ("shallot", "layers"), people of interest ("vigil", "quarry").
