from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from autocage_inspect.diagnostics import (
    FRAME_MARKER,
    DiagnosticFrameError,
    parse_diagnostic_frame,
    persist_diagnostic_frame,
)


def make_frame(sample_id: str = "sample-1", *, truncated: bool = False) -> str:
    data = b"synthetic diagnostic bytes\n"
    item = {
        "data_base64": base64.b64encode(data).decode("ascii"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "captured_bytes": len(data),
        "source_bytes": len(data) + int(truncated),
        "truncated": truncated,
    }
    value = {
        "schema_version": 1,
        "sample_id": sample_id,
        "metadata": {"sample_id": sample_id, "model": "synthetic-test-model"},
        "artifacts": {"aider-stdout.bin": item},
    }
    return FRAME_MARKER + json.dumps(value, sort_keys=True)


class DiagnosticsTests(unittest.TestCase):
    def test_frame_identity_and_content_are_checked(self) -> None:
        frame = parse_diagnostic_frame(make_frame(), "sample-1")
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame["artifacts"]["aider-stdout.bin"]["data"], b"synthetic diagnostic bytes\n")
        with self.assertRaises(DiagnosticFrameError):
            parse_diagnostic_frame(make_frame(), "other-sample")
        mismatched_metadata = json.loads(make_frame().removeprefix(FRAME_MARKER))
        mismatched_metadata["metadata"]["sample_id"] = "other-sample"
        with self.assertRaisesRegex(DiagnosticFrameError, "metadata sample identity"):
            parse_diagnostic_frame(FRAME_MARKER + json.dumps(mismatched_metadata), "sample-1")

    def test_missing_frame_is_not_a_capture_pass(self) -> None:
        self.assertIsNone(parse_diagnostic_frame("ordinary output", "sample-1"))

    def test_corrupt_hash_and_duplicate_frames_are_rejected(self) -> None:
        bad = json.loads(make_frame().removeprefix(FRAME_MARKER))
        bad["artifacts"]["aider-stdout.bin"]["sha256"] = "0" * 64
        with self.assertRaises(DiagnosticFrameError):
            parse_diagnostic_frame(FRAME_MARKER + json.dumps(bad), "sample-1")
        with self.assertRaises(DiagnosticFrameError):
            parse_diagnostic_frame(make_frame() + "\n" + make_frame(), "sample-1")

    def test_truncated_artifact_is_partial_not_complete(self) -> None:
        frame = parse_diagnostic_frame(make_frame(truncated=True), "sample-1")
        assert frame is not None
        with tempfile.TemporaryDirectory() as temporary:
            result = persist_diagnostic_frame(Path(temporary), frame)
            self.assertEqual(result["status"], "PARTIAL")
            artifact = Path(result["artifacts"]["aider-stdout.bin"]["path"])
            self.assertEqual(artifact.read_bytes(), b"synthetic diagnostic bytes\n")
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertEqual(artifact.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(result["manifest"]).stat().st_mode & 0o777, 0o600)

    def test_persistence_never_overwrites_existing_diagnostics(self) -> None:
        frame = parse_diagnostic_frame(make_frame(), "sample-1")
        assert frame is not None
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "diagnostics").mkdir(mode=0o700)
            with self.assertRaises(FileExistsError):
                persist_diagnostic_frame(root, frame)


if __name__ == "__main__":
    unittest.main()
