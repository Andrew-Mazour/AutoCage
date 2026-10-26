"""Bounded, opt-in local-agent diagnostics returned through stdout.

The frame is untrusted sandbox-side data. The controller validates its shape
and hashes, then persists it with restrictive permissions. Hash validation is
not a signature and does not make agent-produced contents trustworthy.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


FRAME_MARKER = "AUTOCAGE_AGENT_DIAGNOSTICS_V1="
MAX_FRAME_BYTES = 4 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 2500 * 1024
ARTIFACT_LIMITS = {
    "aider-chat-history.md": 512 * 1024,
    "aider-llm-history.log": 512 * 1024,
    "aider-stdout.bin": 256 * 1024,
    "aider-stderr.bin": 256 * 1024,
    "ollama-server.log": 256 * 1024,
    "ollama-model-info.json": 64 * 1024,
    "effective-settings.json": 16 * 1024,
}
REQUIRED_ARTIFACTS = {
    "aider-chat-history.md",
    "aider-llm-history.log",
    "aider-stdout.bin",
    "aider-stderr.bin",
    "ollama-server.log",
    "ollama-model-info.json",
    "effective-settings.json",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DiagnosticFrameError(ValueError):
    """The optional diagnostic frame is malformed or does not match its run."""


def parse_diagnostic_frame(stdout: str, expected_sample_id: str) -> dict[str, Any] | None:
    """Parse one bounded frame. Return None when no frame was emitted."""
    matches = [line[len(FRAME_MARKER):] for line in stdout.splitlines() if line.startswith(FRAME_MARKER)]
    if not matches:
        return None
    if len(matches) != 1:
        raise DiagnosticFrameError("multiple diagnostic frames were emitted")
    encoded = matches[0].encode("utf-8")
    if len(encoded) > MAX_FRAME_BYTES:
        raise DiagnosticFrameError("diagnostic frame exceeds the controller size limit")
    try:
        frame = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise DiagnosticFrameError("diagnostic frame is not valid JSON") from error
    if (
        not isinstance(frame, dict)
        or type(frame.get("schema_version")) is not int
        or frame["schema_version"] != 1
    ):
        raise DiagnosticFrameError("unsupported diagnostic frame schema")
    if frame.get("sample_id") != expected_sample_id:
        raise DiagnosticFrameError("diagnostic frame sample identity does not match")
    metadata = frame.get("metadata")
    if not isinstance(metadata, dict) or len(json.dumps(metadata)) > 16 * 1024:
        raise DiagnosticFrameError("diagnostic metadata is missing or oversized")
    if metadata.get("sample_id") != expected_sample_id:
        raise DiagnosticFrameError("diagnostic metadata sample identity does not match")
    artifacts = frame.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) - set(ARTIFACT_LIMITS):
        raise DiagnosticFrameError("diagnostic artifact list is invalid")
    total = 0
    decoded: dict[str, dict[str, Any]] = {}
    for name, item in artifacts.items():
        if not isinstance(item, dict) or set(item) != {
            "data_base64", "sha256", "captured_bytes", "source_bytes", "truncated"
        }:
            raise DiagnosticFrameError(f"diagnostic metadata is invalid for {name}")
        data_text = item["data_base64"]
        if not isinstance(data_text, str):
            raise DiagnosticFrameError(f"diagnostic payload is invalid for {name}")
        try:
            data = base64.b64decode(data_text, validate=True)
        except (ValueError, binascii.Error) as error:
            raise DiagnosticFrameError(f"diagnostic payload is not valid base64 for {name}") from error
        if len(data) > ARTIFACT_LIMITS[name] or len(data) > MAX_TOTAL_ARTIFACT_BYTES - total:
            raise DiagnosticFrameError("diagnostic artifacts exceed the controller size limit")
        if type(item["captured_bytes"]) is not int or item["captured_bytes"] != len(data) or type(item["source_bytes"]) is not int:
            raise DiagnosticFrameError(f"diagnostic byte counts do not match for {name}")
        if type(item["truncated"]) is not bool or item["source_bytes"] < len(data):
            raise DiagnosticFrameError(f"diagnostic truncation metadata is invalid for {name}")
        if not item["truncated"] and item["source_bytes"] != len(data):
            raise DiagnosticFrameError(f"untruncated diagnostic byte count is inconsistent for {name}")
        digest = hashlib.sha256(data).hexdigest()
        if not isinstance(item["sha256"], str) or not _SHA256.fullmatch(item["sha256"]) or digest != item["sha256"]:
            raise DiagnosticFrameError(f"diagnostic content hash does not match for {name}")
        decoded[name] = {"data": data, "sha256": digest, "source_bytes": item["source_bytes"],
                         "truncated": item["truncated"]}
        total += len(data)
    return {"metadata": metadata, "artifacts": decoded}


def persist_diagnostic_frame(root: Path, frame: dict[str, Any]) -> dict[str, Any]:
    """Persist already validated artifacts without following or overwriting paths."""
    directory = root / "diagnostics"
    directory.mkdir(mode=0o700)
    artifacts: dict[str, Any] = {}
    for name, item in frame["artifacts"].items():
        path = directory / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(item["data"])
            output.flush()
            os.fsync(output.fileno())
        artifacts[name] = {
            "path": str(path),
            "sha256": item["sha256"],
            "captured_bytes": len(item["data"]),
            "source_bytes": item["source_bytes"],
            "truncated": item["truncated"],
            "provenance": "untrusted sandbox-side agent/tool output",
        }
    missing = sorted(REQUIRED_ARTIFACTS - set(artifacts))
    empty_required = sorted(
        name for name in ("aider-chat-history.md", "aider-llm-history.log", "effective-settings.json")
        if name in artifacts and artifacts[name]["source_bytes"] == 0
    )
    truncated = sorted(name for name, item in artifacts.items() if item["truncated"])
    complete = not missing and not empty_required and not truncated
    manifest = {
        "schema_version": 1,
        "status": "CAPTURED" if complete else "PARTIAL",
        "sample_id": frame["metadata"].get("sample_id"),
        "metadata": frame["metadata"],
        "metadata_provenance": "untrusted sandbox-side launcher declaration",
        "integrity": "controller recomputed artifact hashes after transfer; frame is not signed",
        "missing_required_artifacts": missing,
        "empty_required_artifacts": empty_required,
        "truncated_artifacts": truncated,
        "artifacts": artifacts,
    }
    manifest_path = directory / "controller-manifest.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(manifest_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(manifest, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    return {"status": manifest["status"], "manifest": str(manifest_path), "artifacts": artifacts,
            "metadata": manifest["metadata"], "integrity": manifest["integrity"]}
