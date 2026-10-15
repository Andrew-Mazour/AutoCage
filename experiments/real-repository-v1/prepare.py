#!/usr/bin/env python3
"""Fetch pinned source objects and prepare immutable real-repository fixtures.

This script only reads Git objects and materializes files. It never imports,
builds, or executes code from an evaluated repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
TASKS_FILE = HERE / "tasks.json"


def run(args: list[str], *, cwd: Path | None = None) -> bytes:
    result = subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE)
    return result.stdout


def git(repo: Path, *args: str) -> bytes:
    return run(["git", "-C", str(repo), *args])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode()
        st = path.lstat()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        digest.update((st.st_mode & 0o7777).to_bytes(4, "big"))
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def content_tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix().encode()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        if path.is_symlink():
            digest.update(b"L")
            digest.update(os.readlink(path).encode())
        elif path.is_dir():
            digest.update(b"D")
        elif path.is_file():
            digest.update(b"F")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def tree_stats(root: Path) -> dict[str, int]:
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    directories = [path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()]
    return {"regular_files": len(files), "directories": len(directories), "bytes": sum(path.stat().st_size for path in files)}


def safe_extract(archive: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
                raise ValueError(f"unsafe Git archive member: {member.name!r}")
            target = destination.joinpath(*rel.parts)
            resolved_parent = target.parent.resolve()
            if resolved_parent != root and root not in resolved_parent.parents:
                raise ValueError(f"archive path escapes destination: {member.name!r}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f"missing archive data: {member.name!r}")
                target.write_bytes(source.read())
                target.chmod(member.mode & 0o777)
            elif member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute():
                    raise ValueError(f"absolute symlink in repository: {member.name!r}")
                stack = list(rel.parent.parts)
                for component in link.parts:
                    if component == "..":
                        if not stack:
                            raise ValueError(f"escaping symlink in repository: {member.name!r}")
                        stack.pop()
                    elif component not in ("", "."):
                        stack.append(component)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
            else:
                raise ValueError(f"unsupported archive entry: {member.name!r}")


def ensure_repo(repo_root: Path, name: str, url: str, commits: set[str]) -> Path:
    path = repo_root / name
    if not (path / ".git").exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "init", str(path)])
        git(path, "remote", "add", "origin", url)
    configured = git(path, "remote", "get-url", "origin").decode().strip()
    if configured != url:
        raise ValueError(f"remote mismatch for {name}: {configured}")
    for commit in sorted(commits):
        exists = subprocess.run(
            ["git", "-C", str(path), "cat-file", "-e", f"{commit}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not exists:
            fetched = subprocess.run(
                ["git", "-C", str(path), "fetch", "--depth=1", "origin", commit],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if fetched.returncode != 0:
                # GitHub may refuse an unadvertised historical SHA even when
                # it is reachable from the default branch. Deepen once, then
                # require the pinned object to exist; never substitute HEAD.
                run(["git", "-C", str(path), "fetch", "--unshallow", "origin"])
                if subprocess.run(
                    ["git", "-C", str(path), "cat-file", "-e", f"{commit}^{{commit}}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                ).returncode != 0:
                    raise ValueError(f"pinned commit is not reachable for {name}: {commit}")
    return path


def commit_entry(repo: Path, commit: str, relative: str) -> tuple[bool, str | None, int | None]:
    found = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{commit}:{relative}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not found:
        return False, None, None
    row = git(repo, "ls-tree", "-r", commit, "--", relative).decode().rstrip("\n")
    if not row:
        raise ValueError(f"Git object exists but tree entry is missing: {commit}:{relative}")
    mode = int(row.split(" ", 1)[0], 8)
    if mode not in (0o100644, 0o100755):
        raise ValueError(f"only regular source files are supported in scripted patches: {relative}")
    content = git(repo, "show", f"{commit}:{relative}")
    return True, base64.b64encode(content).decode("ascii"), mode & 0o777


def agent_actions(repo: Path, task: dict) -> list[dict]:
    actions = []
    for relative in task["patch_paths"]:
        safe = PurePosixPath(relative)
        if safe.is_absolute() or any(part in ("", ".", "..") for part in safe.parts):
            raise ValueError(f"unsafe changed path in task definition: {relative}")
        was_present, _, _ = commit_entry(repo, task["parent"], relative)
        is_present, content, mode = commit_entry(repo, task["target"], relative)
        if was_present and is_present:
            action = {"operation": "write_existing", "path": relative, "content_base64": content, "mode": mode}
        elif not was_present and is_present:
            action = {"operation": "create", "path": relative, "content_base64": content, "mode": mode}
        elif was_present and not is_present:
            action = {"operation": "delete", "path": relative}
        else:
            raise ValueError(f"changed path is absent from both pinned commits: {relative}")
        actions.append(action)
    return actions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-root", type=Path, default=Path("/tmp/autocage-real-repository-v1"))
    args = parser.parse_args()
    manifest = json.loads(TASKS_FILE.read_text())
    work_root = args.work_root.resolve()
    repos_root = work_root / "git-objects"
    workspaces_root = work_root / "workspaces"
    workspaces_root.mkdir(parents=True, exist_ok=True)
    fixtures_root = HERE / "fixtures"
    repo_specs = {}
    for task in manifest["tasks"]:
        spec = repo_specs.setdefault(
            task["repository"], {"url": task["url"], "commits": set()}
        )
        if spec["url"] != task["url"]:
            raise ValueError(f"inconsistent URLs for {task['repository']}")
        spec["commits"].update((task["parent"], task["target"]))

    repos = {
        name: ensure_repo(repos_root, name, spec["url"], spec["commits"])
        for name, spec in sorted(repo_specs.items())
    }
    reports = []
    for task in manifest["tasks"]:
        repo = repos[task["repository"]]
        fixture_dir = fixtures_root / task["id"]
        workspace = workspaces_root / task["id"]
        if fixture_dir.exists():
            shutil.rmtree(fixture_dir)
        if workspace.exists():
            shutil.rmtree(workspace)
        fixture_dir.mkdir(parents=True)
        workspace.mkdir(parents=True)
        base_archive = git(repo, "archive", "--format=tar", task["parent"])
        safe_extract(base_archive, workspace)
        generated_files = []
        for generated in task.get("pre_test_files", []):
            relative = PurePosixPath(generated["path"])
            if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
                raise ValueError(f"unsafe generated test prerequisite path: {generated['path']}")
            target = workspace.joinpath(*relative.parts)
            if target.exists() or target.is_symlink():
                raise ValueError(f"generated test prerequisite already exists: {generated['path']}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(generated["content"])
            target.chmod(generated.get("mode", 0o644))
            generated_files.append({
                "path": generated["path"],
                "sha256": sha256(generated["content"].encode()),
                "mode": generated.get("mode", 0o644),
                "reason": generated["reason"],
            })
        verifier_root = task["verifier_root"]
        test_archive = git(repo, "archive", "--format=tar", task["target"], verifier_root)
        safe_extract(test_archive, workspace)

        diff = git(
            repo,
            "diff",
            "--binary",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            task["parent"],
            task["target"],
            "--",
            *task["patch_paths"],
        )
        if not diff:
            raise ValueError(f"empty production patch for {task['id']}")
        (fixture_dir / "task.patch").write_bytes(diff)
        actions = agent_actions(repo, task)
        actions_bytes = json.dumps(actions, sort_keys=True, separators=(",", ":")).encode()
        (fixture_dir / "agent-actions.json").write_bytes(actions_bytes)
        license_evidence = []
        for license_path in task.get("license_paths", []):
            license_bytes = git(repo, "show", f"{task['parent']}:{license_path}")
            if not license_bytes.strip():
                raise ValueError(f"empty license file for {task['repository']}: {license_path}")
            license_evidence.append({"path": license_path, "sha256": sha256(license_bytes)})
        input_digest = tree_digest(workspace)
        verifier_digest = content_tree_digest(workspace / verifier_root)
        fixture = {
            **task,
            "license_evidence": license_evidence,
            "patch_sha256": sha256(diff),
            "agent_actions_sha256": sha256(actions_bytes),
            "agent_actions": [{key: value for key, value in action.items() if key != "content_base64"} for action in actions],
            "input_tree_sha256": input_digest,
            "source_tree_stats": tree_stats(workspace),
            "verifier_content_sha256": verifier_digest,
            "prepared_test_roots": [verifier_root],
            "generated_test_prerequisites": generated_files,
            "construction": (
                "parent commit snapshot; target commit's complete verifier tree overlaid; "
                "agent patch is the pinned upstream diff restricted to patch_paths"
            ),
        }
        (fixture_dir / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")
        reports.append(
            {
                "task": task["id"],
                "repository": task["repository"],
                "parent": task["parent"],
                "target": task["target"],
                "license": task["license"],
                "license_evidence": license_evidence,
                "patch_sha256": fixture["patch_sha256"],
                "agent_actions_sha256": fixture["agent_actions_sha256"],
                "input_tree_sha256": input_digest,
                "source_tree_stats": fixture["source_tree_stats"],
                "verifier_content_sha256": verifier_digest,
                "patch_bytes": len(diff),
            }
        )

    repository_evidence = {}
    for task in manifest["tasks"]:
        repository_evidence.setdefault(
            task["repository"],
            {
                "url": task["url"],
                "license": task["license"],
                "license_evidence": json.loads((fixtures_root / task["id"] / "fixture.json").read_text())["license_evidence"],
            },
        )
    output = {
        "schema_version": 1,
        "suite_id": manifest["suite_id"],
        "tasks_sha256": sha256(TASKS_FILE.read_bytes()),
        "repositories": repository_evidence,
        "tasks": reports,
    }
    (fixtures_root / "prepared-manifest.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
