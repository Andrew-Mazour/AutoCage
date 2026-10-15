#!/usr/bin/env python3
"""Materialize only pinned Git archives; never import or execute repo code."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
M3_DIR = HERE.parent / "real-repository-v1"
TASKS_PATH = M3_DIR / "tasks.json"
WORKFLOW_PATH = HERE / "workflow-plan.json"


def load_safe_archive_helpers():
    sys.path.insert(0, str(M3_DIR))
    spec = importlib.util.spec_from_file_location("m3_prepare", M3_DIR / "prepare.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the previously reviewed safe archive extractor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        metadata = path.lstat()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update((metadata.st_mode & 0o7777).to_bytes(4, "big"))
        if path.is_symlink():
            digest.update(path.readlink().as_posix().encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--work-root",
        type=Path,
        default=Path("/tmp/autocage-m36/evaluation"),
        help="guest-local disposable root; must not be inside a host-shared directory",
    )
    parser.add_argument(
        "--git-root",
        type=Path,
        default=Path("/tmp/autocage-real-repository-v1/git-objects"),
    )
    args = parser.parse_args()
    work_root = args.work_root.resolve()
    workspace_root = work_root / "workspaces"
    if workspace_root.exists() and any(workspace_root.iterdir()):
        raise SystemExit(f"refusing to overwrite prepared workspaces at {workspace_root}")
    workspace_root.mkdir(parents=True, exist_ok=True)

    tasks = json.loads(TASKS_PATH.read_text())
    task_by_id = {task["id"]: task for task in tasks["tasks"]}
    workflows = json.loads(WORKFLOW_PATH.read_text())
    helpers = load_safe_archive_helpers()
    prepared = []

    for workflow in workflows["workflows"]:
        task = task_by_id[workflow["task_id"]]
        repo = (args.git_root / task["repository"]).resolve()
        if not (repo / ".git").is_dir():
            raise SystemExit(f"missing prepared Git object store for {task['repository']}: {repo}")
        for revision in ("parent", "target"):
            commit = task[revision]
            snapshot = workspace_root / workflow["id"] / revision
            if snapshot.exists():
                raise SystemExit(f"refusing to overwrite prepared snapshot {snapshot}")
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.mkdir(mode=0o700)
            archive = subprocess.run(
                ["git", "-C", str(repo), "archive", "--format=tar", commit],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            helpers.safe_extract(archive, snapshot)
            additions = []
            if workflow["kind"] == "python-wheel":
                dist = snapshot / "dist"
                if dist.exists() or dist.is_symlink():
                    raise SystemExit(f"pinned source already contains a dist path: {snapshot}")
                dist.mkdir(mode=0o755)
                additions.append(
                    "dist/: pre-created declared wheel output directory for the pinned local build command"
                )
                tests = snapshot / "tests"
                tests.mkdir(parents=True, exist_ok=True)
                verifier = tests / "autocage_m36_verify_wheel.py"
                verifier.write_text(
                    "from pathlib import Path\n"
                    "from zipfile import ZipFile\n"
                    "wheels = sorted(Path('/workspace/dist').glob('*.whl'))\n"
                    "assert len(wheels) == 1, f'expected exactly one wheel, got {wheels}'\n"
                    "with ZipFile(wheels[0]) as archive:\n"
                    "    names = archive.namelist()\n"
                    "assert any(name.endswith('.dist-info/WHEEL') for name in names)\n"
                    "assert any(name.endswith('.dist-info/METADATA') for name in names)\n"
                )
                additions.append(
                    "tests/autocage_m36_verify_wheel.py: trusted read-only controller verifier"
                )
            prepared.append(
                {
                    "workflow_id": workflow["id"],
                    "task_id": task["id"],
                    "repository": task["repository"],
                    "revision": revision,
                    "commit": commit,
                    "url": task["url"],
                    "license": task["license"],
                    "snapshot_sha256": digest_tree(snapshot),
                    "snapshot_path": str(snapshot),
                    "experiment_fixture_additions": additions,
                }
            )

    manifest = {
        "schema_version": 1,
        "suite_id": workflows["suite_id"],
        "workflow_plan_sha256": hashlib.sha256(WORKFLOW_PATH.read_bytes()).hexdigest(),
        "source_task_manifest_sha256": hashlib.sha256(TASKS_PATH.read_bytes()).hexdigest(),
        "archive_extraction": "Git archive bytes only; extracted with the M3 reviewed safe extractor; no repository code imported or executed",
        "snapshots": prepared,
    }
    out = work_root / "prepared-manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"prepared {len(prepared)} snapshots at {workspace_root}")
    print(f"manifest: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
