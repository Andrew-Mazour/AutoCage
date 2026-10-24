#!/usr/bin/env python3
"""Fetch and verify the pinned Ollama ARM64 runtime in bounded HTTP ranges."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import subprocess
from pathlib import Path


VERSION = "0.40.4"
SIZE = 1_555_988_008
SHA256 = "1a314ac530d2c23bf6d2aaaf4a4aba8cc0b2a4ee8bc8fae3f3aa88bff7f7177b"
URL = f"https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-linux-arm64.tar.zst"
CHUNK_SIZE = 64 * 1024 * 1024


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def fetch_chunk(index: int, directory: Path) -> Path:
    start = index * CHUNK_SIZE
    end = min(start + CHUNK_SIZE, SIZE) - 1
    expected = end - start + 1
    target = directory / f"part-{index:04d}"
    if target.is_file() and target.stat().st_size == expected:
        return target
    target.unlink(missing_ok=True)
    subprocess.run(
        [
            "curl",
            "--http1.1",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--retry",
            "3",
            "--retry-all-errors",
            "--connect-timeout",
            "20",
            "--max-time",
            "180",
            "--range",
            f"{start}-{end}",
            "--output",
            str(target),
            URL,
        ],
        check=True,
    )
    actual = target.stat().st_size if target.is_file() else 0
    if actual != expected:
        raise RuntimeError(
            f"range {start}-{end} returned {actual} bytes; expected {expected}"
        )
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("/tmp/ollama-linux-arm64.tar.zst"))
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/ollama-arm64-chunks"))
    parser.add_argument("--workers", type=int, default=2)
    options = parser.parse_args()
    if not 1 <= options.workers <= 4:
        parser.error("--workers must be between 1 and 4")
    options.work_dir.mkdir(parents=True, exist_ok=True)
    count = (SIZE + CHUNK_SIZE - 1) // CHUNK_SIZE
    parts: list[Path | None] = [None] * count
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.workers) as pool:
        futures = {
            pool.submit(fetch_chunk, index, options.work_dir): index
            for index in range(count)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            parts[index] = future.result()
            print(f"downloaded range {index + 1}/{count}", flush=True)
    temporary = options.output.with_suffix(options.output.suffix + ".assembling")
    with temporary.open("wb") as output:
        for part in parts:
            assert part is not None
            with part.open("rb") as source:
                while block := source.read(1024 * 1024):
                    output.write(block)
    if temporary.stat().st_size != SIZE:
        raise RuntimeError(f"assembled size mismatch: {temporary.stat().st_size} != {SIZE}")
    actual_digest = digest(temporary)
    if actual_digest != SHA256:
        raise RuntimeError(f"SHA-256 mismatch: {actual_digest}")
    temporary.replace(options.output)
    print(f"verified Ollama {VERSION} ARM64: sha256:{actual_digest} ({SIZE} bytes)")
    print(f"archive: {options.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
