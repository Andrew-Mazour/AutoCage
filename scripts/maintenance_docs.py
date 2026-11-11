#!/usr/bin/env python3
"""Plan/apply deterministic, narrowly-scoped Markdown link-case repairs."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
from urllib.parse import quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL_DOCS = {"README.md", "CHANGELOG.md", "SECURITY.md"}
EXTRA_DOCS = {
    "integrations/inspect_autocage/README.md",
    "examples/byo-repository/README.md",
}
SCHEDULE_HOURS = (2, 8, 14, 20)
SCHEDULE_MINUTE = 17
MIN_CANDIDATES = 3
MAX_CANDIDATES = 10
LINK = re.compile(r"(?P<target><[^>\n]+>|[^)\s]+)(?P<suffix>[^)\n]*\))")
LINK_OPEN = re.compile(r"!?\[[^\]\n]*\]\(")
INLINE_CODE = re.compile(r"(?P<ticks>`+)(?P<body>[^`\n]*?)(?P=ticks)(?!`)")
FENCE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})")


def _utc_date(value: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as error:
        raise ValueError("date must use YYYY-MM-DD") from error


def _documents(root: Path) -> list[Path]:
    result = [root / name for name in sorted(TOP_LEVEL_DOCS) if (root / name).is_file()]
    docs = root / "docs"
    if docs.is_dir() and not docs.is_symlink():
        result.extend(path for path in docs.rglob("*.md") if path.is_file() and not path.is_symlink())
    result.extend(root / name for name in sorted(EXTRA_DOCS) if (root / name).is_file())
    return sorted(set(result), key=lambda path: path.relative_to(root).as_posix())


def _allowed_document_path(value: str) -> bool:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        return False
    if value in TOP_LEVEL_DOCS or value in EXTRA_DOCS:
        return True
    return len(path.parts) >= 2 and path.parts[0] == "docs" and path.suffix.lower() == ".md"


def _mask_code(text: str) -> str:
    chars = list(text)
    offset = 0
    fence_char: str | None = None
    fence_length = 0
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        match = FENCE.match(content)
        mask_line = False
        if fence_char is None and match:
            marker = match.group("marker")
            fence_char, fence_length = marker[0], len(marker)
            mask_line = True
        elif fence_char is not None:
            mask_line = True
            if match:
                marker = match.group("marker")
                tail = content[match.end():]
                if marker[0] == fence_char and len(marker) >= fence_length and not tail.strip():
                    fence_char = None
                    fence_length = 0
        if mask_line:
            for index in range(offset, offset + len(content)):
                chars[index] = " "
        offset += len(line)
    masked = "".join(chars)
    chars = list(masked)
    for match in INLINE_CODE.finditer(masked):
        for index in range(match.start(), match.end()):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _resolve_link(root: Path, document: Path, encoded_path: str) -> tuple[Path | None, bool]:
    """Resolve a relative path without following symlinks; report case mismatches."""
    parsed = urlsplit(encoded_path)
    decoded_path = unquote(parsed.path)
    if parsed.scheme or parsed.netloc or not decoded_path or decoded_path.startswith("/"):
        return None, False
    parts = list(document.relative_to(root).parent.parts)
    changed_case = False
    for component in PurePosixPath(decoded_path).parts:
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                return None, False
            parts.pop()
            continue
        current = root.joinpath(*parts)
        try:
            names = [child.name for child in current.iterdir()]
        except OSError:
            return None, False
        if component in names:
            chosen = component
        else:
            matches = [name for name in names if name.casefold() == component.casefold()]
            if len(matches) != 1:
                return None, False
            chosen = matches[0]
            changed_case = True
        next_path = current / chosen
        if next_path.is_symlink():
            return None, False
        parts.append(chosen)
    target = root.joinpath(*parts)
    if not target.exists() or not (target.is_file() or target.is_dir()):
        return None, False
    return target, changed_case


def _canonical_target(root: Path, document: Path, old_target: str) -> str | None:
    wrapped = old_target.startswith("<") and old_target.endswith(">")
    raw = old_target[1:-1] if wrapped else old_target
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or not parsed.path or parsed.path.startswith("/"):
        return None
    target, changed_case = _resolve_link(root, document, parsed.path)
    if target is None or not changed_case:
        return None
    relative = posixpath.relpath(
        target.relative_to(root).as_posix(),
        document.parent.relative_to(root).as_posix() or ".",
    )
    replacement_path = quote(relative, safe="/._-~")
    replacement = urlunsplit(("", "", replacement_path, parsed.query, parsed.fragment))
    return f"<{replacement}>" if wrapped else replacement


def _scan(root: Path) -> list[dict[str, object]]:
    root = root.resolve(strict=True)
    grouped: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    for document in _documents(root):
        relative = document.relative_to(root).as_posix()
        text = document.read_text(encoding="utf-8")
        masked = _mask_code(text)
        cursor = 0
        while True:
            opening = LINK_OPEN.search(masked, cursor)
            if opening is None:
                break
            target_match = LINK.search(masked, opening.end())
            if target_match is None:
                cursor = opening.end()
                continue
            old_target = target_match.group("target")
            replacement = _canonical_target(root, document, old_target)
            if replacement is not None:
                key = (relative, old_target, replacement)
                grouped.setdefault(key, []).append((target_match.start("target"), target_match.end("target")))
            cursor = target_match.end()
    candidates = []
    for (path, old_target, new_target), spans in sorted(grouped.items()):
        identity = json.dumps([path, old_target, new_target], separators=(",", ":"))
        candidates.append({
            "id": hashlib.sha256(identity.encode()).hexdigest(),
            "file": path,
            "old_target": old_target,
            "new_target": new_target,
            "occurrences": len(spans),
            "_spans": spans,
        })
    return candidates


def _selection(root: Path, run_date: date, seed: str, candidates: list[dict[str, object]]) -> dict[str, object]:
    request_hash = hashlib.sha256(f"autocage-doc-maintenance-v1:{root.name}:{run_date.isoformat()}:{seed}".encode()).hexdigest()
    requested = MIN_CANDIDATES + int(request_hash[:8], 16) % (MAX_CANDIDATES - MIN_CANDIDATES + 1)
    if len(candidates) < MIN_CANDIDATES:
        chosen: list[dict[str, object]] = []
    else:
        chosen = sorted(
            candidates,
            key=lambda item: hashlib.sha256(f"{seed}:{item['id']}".encode()).hexdigest(),
        )[:min(requested, len(candidates))]
    public = [
        {key: item[key] for key in ("file", "old_target", "new_target", "occurrences")}
        for item in chosen
    ]
    plan_digest = hashlib.sha256(json.dumps(public, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "date": run_date.isoformat(),
        "seed": seed,
        "eligible_count": len(candidates),
        "requested_count": requested,
        "selected_count": len(chosen),
        "plan_digest": plan_digest,
        "selected": public,
        "_selected": chosen,
    }


def _apply(root: Path, plan: dict[str, object]) -> None:
    root = root.resolve(strict=True)
    selected = plan["_selected"]
    assert isinstance(selected, list)
    edits: dict[str, list[tuple[int, int, str]]] = {}
    for candidate in selected:
        assert isinstance(candidate, dict)
        filename = candidate["file"]
        spans = candidate["_spans"]
        new_target = candidate["new_target"]
        assert isinstance(filename, str) and isinstance(spans, list) and isinstance(new_target, str)
        edits.setdefault(filename, []).extend((start, end, new_target) for start, end in spans)
    originals: dict[str, str] = {}
    try:
        for filename, changes in edits.items():
            if not _allowed_document_path(filename):
                raise ValueError(f"maintenance candidate escaped the documentation allowlist: {filename}")
            path = root / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"maintenance candidate is no longer a regular file: {filename}")
            text = path.read_text(encoding="utf-8")
            originals[filename] = text
            for start, end, replacement in sorted(changes, reverse=True):
                text = text[:start] + replacement + text[end:]
            path.write_text(text, encoding="utf-8")
        for candidate in selected:
            assert isinstance(candidate, dict)
            document = root / str(candidate["file"])
            if _canonical_target(root, document, str(candidate["new_target"])) is not None:
                raise ValueError(f"candidate repair did not resolve exactly: {candidate['file']} {candidate['new_target']}")
    except Exception:
        for filename, text in originals.items():
            (root / filename).write_text(text, encoding="utf-8")
        raise


def _schedule_slot(run_date: date) -> str:
    digest = hashlib.sha256(f"autocage-doc-maintenance-slot-v1:{run_date.isoformat()}".encode()).hexdigest()
    hour = SCHEDULE_HOURS[int(digest[:8], 16) % len(SCHEDULE_HOURS)]
    return f"{SCHEDULE_MINUTE:02d} {hour:02d} * * *"


def _validate_diff(root: Path) -> tuple[bool, list[str]]:
    paths: set[str] = set()
    for args in (["diff", "--name-only", "-z"], ["diff", "--cached", "--name-only", "-z"]):
        result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=True)
        paths.update(value for value in result.stdout.decode().split("\0") if value)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root,
        capture_output=True, check=True,
    )
    paths.update(value for value in untracked.stdout.decode().split("\0") if value)
    invalid = sorted(path for path in paths if not _allowed_document_path(path))
    return not invalid, invalid


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dry-run or apply deterministic, allowlisted Markdown link-case repairs")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="report only; this is the default and never writes")
    mode.add_argument("--apply", action="store_true", help="apply selected repairs to the current checkout only")
    mode.add_argument("--slot-for-date", metavar="YYYY-MM-DD", help="print the selected daily cron slot")
    mode.add_argument("--check-diff", action="store_true", help="fail if changed or untracked paths are outside the documentation allowlist")
    parser.add_argument("--date", help="UTC plan date (default: today)")
    parser.add_argument("--seed", default="default", help="stable selection seed")
    parser.add_argument("--json", action="store_true", help="emit a machine-readable plan")
    args = parser.parse_args(argv)
    root = ROOT.resolve(strict=True)
    if args.slot_for_date:
        print(_schedule_slot(_utc_date(args.slot_for_date)))
        return 0
    if args.check_diff:
        valid, invalid = _validate_diff(root)
        if not valid:
            print("Disallowed changed paths: " + ", ".join(invalid), file=sys.stderr)
            return 1
        print("Maintenance diff allowlist: PASS")
        return 0
    run_date = _utc_date(args.date) if args.date else datetime.now(timezone.utc).date()
    candidates = _scan(root)
    plan = _selection(root, run_date, args.seed, candidates)
    public = {key: value for key, value in plan.items() if not key.startswith("_")}
    if args.apply and int(plan["selected_count"]) >= MIN_CANDIDATES:
        _apply(root, plan)
        public["applied"] = True
    else:
        public["applied"] = False
    if args.json:
        print(json.dumps(public, sort_keys=True))
    else:
        print(json.dumps(public, sort_keys=True, indent=2))
        if int(plan["selected_count"]) == 0:
            print("NO ACTION: fewer than three unambiguous, justified repairs are available.")
        elif not args.apply:
            print("DRY RUN: no files were modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
