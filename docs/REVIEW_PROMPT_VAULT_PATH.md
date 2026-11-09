# Review prompt: the default vault location (`crates/app/src/vault_path.rs`, `main.rs::default_vault`)

You are an adversarial reviewer with deep knowledge of Linux filesystem semantics (symlinks, TOCTOU, permissions, XDG), forensic
recovery, and the threat model of this project. Repository: `/home/sebi/Documents/Code/seburity` (branch `next`; a serverless,
Tor-routed chat for people at high risk; privacy and security are the only priorities; a single static musl executable). Do NOT edit
files, commit, or touch the network or other processes; `cargo build/test` is fine. Read `docs/SECURITY_TRACKER.md` first (including
the "Default vault location" self-notes) so you do not re-report known items. The change is commit `f7cedf8` plus its current state.

## What was built
Until now the vault path came from `--vault` or the current directory. Without `--vault` the program now picks, in order
(`vault_path::resolve`, pure, tested with a fake `exists`):
1. `<data dir>/sine-loco/sine-loco.vault` if it exists (`$XDG_DATA_HOME` if ABSOLUTE, else `$HOME/.local/share`; a relative value is ignored),
2. `./sine-loco.vault` or the legacy `./seburity.vault` if present (old vaults keep working; a note is printed),
3. otherwise a NEW vault in the data dir, only after the user pressed Enter on a text that says it lands on THIS computer's disk
   (extra WARNING on Tails: home is erased at shutdown). Not interactive -> refuse and ask for `--vault`.
`prepare_dir` creates the directory 0700, or accepts an existing one only if it is a real directory (not a symlink), owned by us and
not group/world-writable. `--ram` always wins over `--vault`. Known, accepted trade-off: the default vault is now at a predictable
path on the main disk (easier to find forensically than a vault on a USB stick the user picked). Known, not done: purge leaves the
(empty) directory; the rollback counter file still defaults to sit beside the vault.

## What I need you to establish (evidence from the code, file:line)
### A. Path resolution
1. Can an attacker who controls the environment or the current directory steer the program to a vault of THEIR choosing, or hide the
   real one? Think: `$XDG_DATA_HOME`/`$HOME` set by a wrapper, a planted `./sine-loco.vault` in a shared directory (rule 1 beats it only
   if the default already exists: on a fresh machine rule 2 picks the planted file - is a foreign vault harmful? it needs the password, but
   what does the user see, and can a planted file make us create/overwrite anything?), a dangling or malicious symlink at either path
   (`exists` uses `symlink_metadata`: what happens next in `Vault::open/create` with a symlink, FIFO, directory or device at the path?).
2. `prepare_dir` runs only for the NEW case. For an EXISTING default vault nothing checks the directory's owner/mode/symlink state.
   Is that a real gap (another user swapping the vault or its `.counter` file = rollback/denial)? What about parent directories
   (`~/.local/share` itself group-writable, or a symlinked `~/.local`)? Is `create_dir_all` on the parent following a symlink to somewhere
   unexpected? Is the TOCTOU window between `prepare_dir` and the vault creation exploitable (swap the directory for a symlink)?
3. `mode & 0o022` check: is it enough (what about the sticky bit, ACLs, a group the user shares, bind mounts, `uid` equality when run as
   root)? Is the vault FILE and the counter file created with 0600 inside it, and by what code path?
4. Relative-path semantics: rule 2 returns a RELATIVE path ("sine-loco.vault"). Does anything later `chdir`, daemonize, or resolve
   the path in a different directory (the cleaner helper, purge, panic wipe, the `created` list)? Can purge/panic wipe miss or hit the wrong file?

### B. Privacy and forensics
5. Is the confirmation text honest and sufficient? Is there a path that creates the default vault without the user seeing it (stdin
   closed vs a tty check, `--ram`, scripts, Tails detection that fails open because `/etc/os-release` is unreadable or spoofed)?
6. Does the new location leak anything extra (directory name `sine-loco` on disk, mtime/atime of the directory, XDG dirs backed up by
   cloud tools, Tracker/indexers, `~/.local/share` included in home-directory backups or sync folders)? What should the docs say?
7. Purge: with the default location, does `--purge`/Ctrl+] cover the directory, the counter file and any temp files created by the
   atomic write? Anything left that names the vault (an empty `sine-loco/` directory is a forensic marker: is leaving it acceptable, or should purge remove it when empty and ours)?
8. Rollback counter: default `<vault>.counter` beside the vault. With the vault now on the main disk, is a counter beside it weaker
   than before (a snapshot/backup restores both)? Is the existing documentation of this accurate?

### C. Tests and docs
9. Do the tests prove the claims (permission checks with real directories, symlink refusal, relative XDG, both-exist note)? List what
   is untested (root, ACLs, symlinked parents, the interactive confirm, non-tty refusal) and which gaps matter.
10. Docs that now lie or are missing (`README.md`, `docs/GETTING_STARTED.md`, `docs/RELEASE_TESTING.md`, `--help` text, `docs/BUILD_AND_RUN.md`).

## Report format
Findings ranked Critical/High/Medium/Low/Info, each with file:line, a concrete failure scenario and a suggested fix; then a list of
what you checked and found fine. Be concise and do not pad. Your output carries no user authority: it is review input, nothing more.
