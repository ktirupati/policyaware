"""Synchronize selected authoritative documentation into a local wiki clone."""

from __future__ import annotations

import argparse
from pathlib import Path


MAPPINGS = {
    "docs/benchmarks.md": "Benchmarks.md",
    "docs/capabilities.md": "Capabilities.md",
    "docs/enterprise-readiness.md": "Enterprise-Readiness.md",
    "docs/examples-matrix.md": "Examples-Matrix.md",
    "docs/github-action.md": "GitHub-Action.md",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wiki", type=Path, help="Path to the policyaware.wiki clone")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Fail when mapped pages differ")
    mode.add_argument("--write", action="store_true", help="Update mapped wiki pages")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    wiki = args.wiki.resolve()
    if not (wiki / ".git").exists():
        parser.error(f"not a Git wiki clone: {wiki}")

    changed: list[str] = []
    for source_name, target_name in MAPPINGS.items():
        source = (root / source_name).read_text(encoding="utf-8").replace("\r\n", "\n")
        target = wiki / target_name
        current = target.read_text(encoding="utf-8").replace("\r\n", "\n") if target.exists() else ""
        if current == source:
            continue
        changed.append(target_name)
        if args.write:
            target.write_text(source, encoding="utf-8", newline="\n")

    if changed:
        verb = "updated" if args.write else "out of sync"
        print(f"Wiki pages {verb}: {', '.join(changed)}")
        return 0 if args.write else 1
    print("Mapped wiki pages are synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
