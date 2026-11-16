#!/usr/bin/env python3
"""Check that internal documentation links resolve.

Corvi's ADRs link to each other, to JSON Schemas and to deployment examples.
A broken link is a design defect: it hides a contract from the reader who
needs it. This script fails when a relative link points at a file that does not
exist.

Only relative links are checked. External URLs are not fetched, so the script
runs offline and deterministically.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Markdown inline links and reference definitions.
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# Bare paths in link targets such as <docs/adr/0001-....md>.
ANGLE_PATTERN = re.compile(r"<(docs/[^>]+|api/[^>]+|deploy/[^>]+)>")

# Fragments inside a document are not files; strip them before checking.
IGNORED_SCHEMES = ("http://", "https://", "mailto:", "tel:", "#")


def candidate_paths(target: str) -> list[Path]:
    """Return the paths a link target could refer to."""
    if target.startswith(IGNORED_SCHEMES):
        return []

    # Drop a URL fragment and any query string.
    clean = target.split("#", 1)[0].split("?", 1)[0]
    if not clean:
        return []

    return [Path(clean)]


def iter_documents() -> list[Path]:
    """Every markdown file that is part of the repository."""
    skip = {".git", "target", "node_modules"}
    documents = []
    for path in ROOT.rglob("*.md"):
        if any(part in skip for part in path.relative_to(ROOT).parts):
            continue
        documents.append(path)
    return sorted(documents)


def main() -> int:
    failures: list[str] = []
    checked = 0

    for document in iter_documents():
        text = document.read_text(encoding="utf-8")

        targets: list[str] = list(LINK_PATTERN.findall(text))
        targets.extend(ANGLE_PATTERN.findall(text))

        for target in targets:
            for candidate in candidate_paths(target):
                checked += 1
                resolved = (document.parent / candidate).resolve()
                if not resolved.exists():
                    failures.append(
                        f"{document.relative_to(ROOT)}: broken link -> {target}"
                    )

    print(f"checked {checked} internal link references across "
          f"{len(iter_documents())} documents")

    if failures:
        print(f"\n{len(failures)} broken link(s):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print("all internal links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
