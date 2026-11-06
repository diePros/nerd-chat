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


def forms_of(name):
    """Every spelling of a project name that occurs in the tree, longest first."""
    kebab, snake = name, name.replace("-", "_")
    out = {kebab, snake, kebab.upper(), snake.upper(), kebab[0].upper() + kebab[1:], snake[0].upper() + snake[1:]}
    return sorted(out, key=len, reverse=True)


def mapping(old, new):
    """(kebab map, snake map): old spelling -> new spelling, form by form (kebab stays kebab, snake stays snake, UPPER stays UPPER, Title stays Title).
    A single-word old name has the SAME kebab and snake spelling, so the replacement is chosen by context (see `main`)."""
    def spell(n, snake):
        n2 = n.replace("-", "_") if snake else n
        return (n2, n2.upper(), n2[0].upper() + n2[1:])
    kebab = dict(zip(spell(old, False), spell(new, False)))
    snake = dict(zip(spell(old, True), spell(new, True)))
    return kebab, snake


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
    # a name that is short, or contains / is contained in the old one, would be replaced inside other words or inside itself
    if len(new) < 4 or new in old or old in new:
        sys.exit(f"refusing {new!r}: it must be at least 4 characters and must not contain, or be contained in, the current name {old!r}")
    if "--dry-run" not in flags and "--force" not in flags:
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if dirty:
            sys.exit("the git working tree is not clean: commit or stash first (so that `git checkout .` can undo the rename), or use --force")

    frozen = sorted((l.strip() for l in (ROOT / "scripts/frozen-labels.txt").read_text().splitlines() if l.strip() and not l.startswith("#")), key=len, reverse=True)
    kebab_map, snake_map = mapping(old, new)

    def replace(m):
        # `old_xyz` (a Rust path, an env var prefix) takes the snake spelling, everything else the kebab one
        nxt = m.string[m.end():m.end() + 1]
        first, second = (snake_map, kebab_map) if nxt == "_" else (kebab_map, snake_map)
        return first.get(m.group(0)) or second[m.group(0)]
    # ONE pass: a single alternation with identifier boundaries, so the output of one replacement is never replaced again and the
    # name is never replaced inside a longer word (`nerd-chats`, `ubernerd-chat`, `nerd_chat2`)
    rx = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(f) for f in forms_of(old)) + r")(?![A-Za-z0-9])")
    newrx = re.compile(r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(f) for f in forms_of(new)) + r")(?![A-Za-z0-9])")
    plan = []
    for p, rel in files():
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        masked = text
        for i, label in enumerate(frozen):  # protect the frozen strings behind placeholders
            masked = masked.replace(label, f"\x00F{i}\x00")
        if newrx.search(masked):
            sys.exit(f"refusing {new!r}: it already occurs in {rel} (the rename would merge it with existing text)")
        out = rx.sub(replace, masked)
        for i, label in enumerate(frozen):
            out = out.replace(f"\x00F{i}\x00", label)
        if out != text:
            plan.append((p, rel, out))
    print(f"{old} -> {new}: {len(plan)} file(s) {'would change' if '--dry-run' in flags else 'changed'}")
    for _, rel, _ in plan:
        print("  ", rel)
    if "--dry-run" in flags:
        return
    for p, _, out in plan:
        p.write_text(out)
    (ROOT / "scripts/project-name.txt").write_text(new + "\n")
    r = subprocess.run(["cargo", "update", "--workspace", "--offline"], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        (ROOT / "scripts/project-name.txt").write_text(old + "\n")
        sys.exit("cargo update FAILED, the tree is NOT in a usable state; undo with `git checkout . && git clean -fd`:\n" + r.stderr)
    print("Cargo.lock refreshed")
    if "--test" in flags:
        sys.exit(subprocess.run(["cargo", "test", "--workspace"], cwd=ROOT).returncode)
    print("Next: cargo test --workspace, rebuild, and rename the GitHub repository if you want it to match.")


if __name__ == "__main__":
    main()
