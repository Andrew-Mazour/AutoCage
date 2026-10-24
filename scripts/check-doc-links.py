#!/usr/bin/env python3
"""Check local Markdown links in current user-facing documentation."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOCUMENTS = [
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    ROOT / "SECURITY.md",
    ROOT / "docs" / "INSTALL.md",
    ROOT / "docs" / "RELEASE.md",
    ROOT / "docs" / "ARCHITECTURE.md",
    ROOT / "docs" / "THREAT_MODEL.md",
    ROOT / "docs" / "ROADMAP.md",
    ROOT / "docs" / "DECISIONS.md",
    ROOT / "docs" / "EVALUATION.md",
    ROOT / "integrations" / "inspect_autocage" / "README.md",
    ROOT / "experiments" / "inspect-autocage-v1" / "README.md",
    ROOT / "experiments" / "inspect-autocage-v1" / "results" / "2026-10-19-m6-quickstart" / "README.md",
]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)|!\[[^\]]*\]\(([^)]+)\)")


def main() -> int:
    failures: list[str] = []
    for document in DOCUMENTS:
        if not document.is_file():
            failures.append(f"missing documentation file: {document.relative_to(ROOT)}")
            continue
        for match in LINK.finditer(document.read_text(encoding="utf-8")):
            target = (match.group(1) or match.group(2)).strip().strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("#"):
                continue
            path = unquote(parsed.path)
            if not path:
                continue
            resolved = (document.parent / path).resolve()
            if not resolved.exists():
                failures.append(
                    f"{document.relative_to(ROOT)}: missing link target {target}"
                )
    if failures:
        print("Documentation links: FAIL")
        print("\n".join(failures))
        return 1
    print(f"Documentation links: PASS ({len(DOCUMENTS)} user-facing files checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
