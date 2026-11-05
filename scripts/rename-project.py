#!/usr/bin/env python3
"""Rename the project (crates, binary, user-visible text, docs, scripts) in one step, without touching the frozen format labels.

    python3 scripts/rename-project.py NEW-NAME            # do it (needs a clean git tree, so `git checkout .` undoes it)
    python3 scripts/rename-project.py NEW-NAME --dry-run  # only list what would change
    python3 scripts/rename-project.py NEW-NAME --test     # afterwards run `cargo test --workspace`

NEW-NAME: lowercase letters, digits and '-', starting with a letter (e.g. `nerd-chat`). The CURRENT name is read from
scripts/project-name.txt (and updated), so the script can be run again and again.

What changes (current name -> new name): Cargo package names and dependency keys, `use` paths (`old_core` -> `new_core`), the binary
name, env var prefixes, the title in the UI, docs, scripts, supply-chain policy keys, Cargo.lock (refreshed offline).
What NEVER changes: the guard test crates/core/tests/frozen_labels.rs, docs/NAMES.md (the history of names), every string in scripts/frozen-labels.txt (disk/wire-format and cryptographic domain-separation labels that contain
the ORIGINAL codename; renaming them would break existing vaults, bundles and handshakes), and `vendor/` (third-party code).
After a rename also rename the GitHub repository by hand if you want them to match.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"target", ".git", "vendor", ".claude"}
EXTS = {".rs", ".toml", ".md", ".sh", ".py", ".txt", ".yml", ".yaml"}
# files that must keep the legacy codename verbatim
SKIP_FILES = {"scripts/frozen-labels.txt", "scripts/rename-project.py", "crates/core/tests/frozen_labels.rs", "docs/NAMES.md", "Cargo.lock", "LICENSE"}


def files():
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if not p.is_file() or any(part in SKIP_DIRS for part in rel.parts) or str(rel) in SKIP_FILES:
            continue
        if p.suffix in EXTS or p.name in {".gitignore"}:
            yield p, str(rel)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if len(args) != 1 or flags - {"--dry-run", "--test", "--force"}:
        sys.exit(__doc__)
    new = args[0]
    if not re.fullmatch(r"[a-z][a-z0-9]*(-[a-z0-9]+)*", new):
        sys.exit("NEW-NAME must be lowercase letters/digits/'-', start with a letter, no trailing or double '-' (e.g. nerd-chat)")
    old = (ROOT / "scripts/project-name.txt").read_text().strip()
    if new == old:
        sys.exit(f"the project is already called {old}")
    if "--dry-run" not in flags and "--force" not in flags:
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if dirty:
            sys.exit("the git working tree is not clean: commit or stash first (so that `git checkout .` can undo the rename), or use --force")

    frozen = [l.strip() for l in (ROOT / "scripts/frozen-labels.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    frozen.sort(key=len, reverse=True)
    old_snake, new_snake = old.replace("-", "_"), new.replace("-", "_")
    forms = [  # most specific first
        (old.upper().replace("-", "_") + "_", new.upper().replace("-", "_") + "_"),   # env vars  OLD_FOO -> NEW_FOO
        (old.upper(), new.upper()),                                                   # display    OLD -> NEW
        (old[0].upper() + old[1:], new[0].upper() + new[1:]),                         # Title
        (old_snake + "_", new_snake + "_"),                                           # Rust paths old_core -> new_core
        (old + "-", new + "-"),                                                       # package names old-core -> new-core
        (old, new),                                                                   # the bare word
    ]
    changed = []
    for p, rel in files():
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        out = text
        for i, label in enumerate(frozen):  # protect the frozen strings behind placeholders
            out = out.replace(label, f"\x00F{i}\x00")
        for a, b in forms:
            out = out.replace(a, b)
        for i, label in enumerate(frozen):
            out = out.replace(f"\x00F{i}\x00", label)
        if out != text:
            changed.append(rel)
            if "--dry-run" not in flags:
                p.write_text(out)
    print(f"{old} -> {new}: {len(changed)} file(s) {'would change' if '--dry-run' in flags else 'changed'}")
    for rel in changed:
        print("  ", rel)
    if "--dry-run" in flags:
        return
    (ROOT / "scripts/project-name.txt").write_text(new + "\n")
    r = subprocess.run(["cargo", "update", "--workspace", "--offline"], cwd=ROOT, capture_output=True, text=True)
    print("Cargo.lock refreshed" if r.returncode == 0 else "WARNING: cargo update failed:\n" + r.stderr)
    if "--test" in flags:
        sys.exit(subprocess.run(["cargo", "test", "--workspace"], cwd=ROOT).returncode)
    print("Next: cargo test --workspace, rebuild, and rename the GitHub repository if you want it to match.")


if __name__ == "__main__":
    main()
