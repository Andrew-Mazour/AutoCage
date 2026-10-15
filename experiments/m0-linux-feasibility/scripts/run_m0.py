#!/usr/bin/env python3
"""Disposable, trusted-controller Bubblewrap feasibility experiment.

This is an experiment harness, not AutoCage runtime code. It uses only Python's
standard library and synthetic data. The controller runs outside Bubblewrap;
it prepares fixtures, launches commands, and checks host-side outcomes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import fcntl
import select
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


NAMESPACES = {
    "user": "--unshare-user",
    "mnt": None,  # Bubblewrap always creates a mount namespace.
    "pid": "--unshare-pid",
    "ipc": "--unshare-ipc",
    "uts": "--unshare-uts",
    "net": "--unshare-net",
}
SYNTHETIC = "AUTOCAGE-M0-SYNTHETIC-CREDENTIAL-CANARY-DO-NOT-USE"
MAX_CAPTURE = 5000


class Controller:
    def __init__(self, lab: Path, bwrap: str, results_path: Path):
        self.lab = lab
        self.bwrap = bwrap
        self.results_path = results_path
        self.tests: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.stage = lab / "stage"
        self.stage_copy = lab / "stage-copy"
        self.original = lab / "original"
        self.host = lab / "host-only"
        self.host_canary = self.host / "credential-canary.txt"
        self.exact_file = self.stage_copy / "src" / "allowed.txt"
        self.out_dir = self.stage_copy / "out"

    def check(self, name: str, passed: bool, detail: str) -> None:
        status = "PASS" if passed else "FAIL"
        self.tests.append({"name": name, "status": status, "detail": detail})

    def note(self, name: str, status: str, detail: str) -> None:
        if status not in {"PASS", "FAIL", "BLOCKED", "NOT TESTED"}:
            raise ValueError("invalid test status")
        self.tests.append({"name": name, "status": status, "detail": detail})

    def command(
        self,
        test_name: str,
        args: list[str],
        *,
        timeout: float = 10.0,
        extra_env: dict[str, str] | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        argv = [self.bwrap, *args]
        command_record: dict[str, Any] = {"test": test_name, "argv": argv, "timeout_seconds": timeout}
        self.commands.append(command_record)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        if extra_env:
            env.update(extra_env)
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                env=env,
                pass_fds=pass_fds,
                check=False,
            )
            command_record.update(
                {
                    "returncode": proc.returncode,
                    "stdout": proc.stdout[-MAX_CAPTURE:],
                    "stderr": proc.stderr[-MAX_CAPTURE:],
                }
            )
            return proc
        except subprocess.TimeoutExpired as exc:
            command_record.update({"timeout": True, "stdout": str(exc.stdout or "")[-MAX_CAPTURE:], "stderr": str(exc.stderr or "")[-MAX_CAPTURE:]})
            return subprocess.CompletedProcess(argv, 124, str(exc.stdout or ""), str(exc.stderr or "timed out"))
        except OSError as exc:
            command_record.update({"spawn_error": repr(exc)})
            return subprocess.CompletedProcess(argv, 127, "", repr(exc))

    def base_args(
        self,
        stage: Path,
        *,
        namespaces: tuple[str, ...] = tuple(NAMESPACES),
        include_etc: bool = True,
        writable_file: Path | None = None,
        writable_dirs: tuple[Path, ...] = (),
        nested_readonly_file: Path | None = None,
    ) -> list[str]:
        args = ["--die-with-parent", "--new-session"]
        for ns in namespaces:
            flag = NAMESPACES[ns]
            if flag:
                args.append(flag)
        # Fail if this required defense cannot be installed; do not accept a
        # Bubblewrap invocation that silently leaves nested userns available.
        args += ["--disable-userns", "--assert-userns-disabled"]

        args += ["--ro-bind", "/usr", "/usr"]
        for target, link in (
            ("usr/bin", "/bin"),
            ("usr/sbin", "/sbin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
        ):
            args += ["--symlink", target, link]
        if include_etc:
            args += ["--ro-bind", "/etc", "/etc"]
        args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/tmp/home"]
        args += ["--ro-bind", str(stage), "/workspace"]
        if writable_file is not None:
            args += ["--bind", str(writable_file), f"/workspace/{writable_file.relative_to(stage).as_posix()}"]
        for directory in writable_dirs:
            args += ["--bind", str(directory), f"/workspace/{directory.relative_to(stage).as_posix()}"]
        if nested_readonly_file is not None:
            args += [
                "--ro-bind",
                str(nested_readonly_file),
                f"/workspace/{nested_readonly_file.relative_to(stage).as_posix()}",
            ]
        args += [
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp/home",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "PWD",
            "/workspace",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--",
        ]
        return args

    def py(self, code: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self.command("python probe", self.base_args(self.stage_copy, **kwargs) + ["/usr/bin/python3", "-c", code])

    def prepare(self, fixture_dir: Path) -> None:
        self.host.mkdir()
        self.host_canary.write_text(SYNTHETIC + "\n", encoding="utf-8")
        self.original.mkdir()
        (self.original / "project.txt").write_text("original checkout must stay unchanged\n", encoding="utf-8")

        self.stage.mkdir()
        (self.stage / "src").mkdir()
        (self.stage / "out").mkdir()
        (self.stage / "links").mkdir()
        (self.stage / "src" / "allowed.txt").write_text("initial staged content\n", encoding="utf-8")
        (self.stage / "src" / "readonly.txt").write_text("read-only sibling\n", encoding="utf-8")
        (self.stage / "src" / "new-file-parent-marker").write_text("parent stays readonly\n", encoding="utf-8")
        (self.stage / "out" / "locked.txt").write_text("nested readonly file\n", encoding="utf-8")
        (self.stage / "out" / "existing.txt").write_text("before\n", encoding="utf-8")
        shutil.copytree(fixture_dir, self.stage / "python-project")

        os.link(self.host_canary, self.stage / "links" / "hardlink-alias.txt")
        (self.stage / "links" / "absolute-escape.txt").symlink_to(self.host_canary)
        (self.stage / "links" / "chain-b.txt").symlink_to("absolute-escape.txt")
        (self.stage / "links" / "chain-a.txt").symlink_to("chain-b.txt")
        shutil.copytree(self.stage, self.stage_copy, symlinks=True)

    def namespace_tests(self) -> bool:
        outer = {name: os.stat(f"/proc/self/ns/{name}").st_ino for name in NAMESPACES}
        for name, flag in NAMESPACES.items():
            source = (
                "import json, os, sys\n"
                "expected=json.loads(sys.argv[1])\n"
                f"actual=os.stat('/proc/self/ns/{name}').st_ino\n"
                "raise SystemExit(0 if actual != expected else 31)\n"
            )
            selected = ("user",) if name == "user" else ("user", name)
            proc = self.command(
                f"{name} namespace unprivileged smoke test",
                self.base_args(self.stage_copy, namespaces=selected) + ["/usr/bin/python3", "-c", source, json.dumps(outer)],
            )
            self.check(
                f"unprivileged {name} namespace",
                proc.returncode == 0,
                f"returncode={proc.returncode}; bwrap error={proc.stderr.strip()[-600:]!r}",
            )

        source = (
            "import json, os, sys\n"
            "expected=json.loads(sys.argv[1])\n"
            "names=('user','mnt','pid','ipc','uts','net')\n"
            "failed=[n for n in names if os.stat('/proc/self/ns/'+n).st_ino == expected[n]]\n"
            "raise SystemExit(0 if not failed else 32)\n"
        )
        proc = self.command(
            "all required namespaces together",
            self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", source, json.dumps(outer)],
        )
        self.check("combined required namespace setup", proc.returncode == 0, f"returncode={proc.returncode}; stderr={proc.stderr.strip()[-600:]!r}")
        combined_ok = proc.returncode == 0

        # Determine whether the host allows nested user namespaces, then verify
        # that a sandbox launched with --disable-userns cannot create one.
        clone_probe = (
            "import ctypes, errno\n"
            "libc=ctypes.CDLL(None, use_errno=True)\n"
            "rc=libc.unshare(0x10000000)\n"
            "err=ctypes.get_errno() if rc != 0 else 0\n"
            "print('NESTED_USERNS_ALLOWED=%d ERRNO=%d' % (1 if rc == 0 else 0, err))\n"
        )
        proc = self.command("nested user namespace blocked by --disable-userns", self.base_args(self.stage_copy, namespaces=("user",)) + ["/usr/bin/python3", "-c", clone_probe])
        # The control is built separately so only the disable flag differs.
        control_args = self.base_args(self.stage_copy, namespaces=("user",))
        control_args.remove("--disable-userns")
        control_args.remove("--assert-userns-disabled")
        control = self.command("nested user namespace control", control_args + ["/usr/bin/python3", "-c", clone_probe])
        try:
            disabled_allowed = "NESTED_USERNS_ALLOWED=1" in proc.stdout
            baseline_allowed = "NESTED_USERNS_ALLOWED=1" in control.stdout
            if proc.returncode != 0 or control.returncode != 0:
                self.note("nested user namespaces denied when --disable-userns is set", "BLOCKED", "Bubblewrap namespace setup failed before the nested-userns probe could execute")
            elif not baseline_allowed:
                self.note("nested user namespaces denied when --disable-userns is set", "BLOCKED", "host policy already rejects nested user namespaces without the flag, so the flag's independent effect cannot be isolated")
            else:
                self.check(
                    "nested user namespaces denied when --disable-userns is set",
                    proc.returncode == 0 and control.returncode == 0 and baseline_allowed and not disabled_allowed,
                    f"with flag: rc={proc.returncode} {proc.stdout.strip() or proc.stderr.strip()}; without flag: rc={control.returncode} {control.stdout.strip() or control.stderr.strip()}",
                )
        except Exception as exc:
            self.check("nested user namespaces denied when --disable-userns is set", False, f"could not interpret nested user namespace probe: {exc!r}")

        cap_probe = (
            "import json\n"
            "d={}\n"
            "for p in ('uid_map','gid_map'):\n"
            " d[p]=open('/proc/self/'+p, encoding='ascii').read().strip().splitlines()\n"
            "for line in open('/proc/self/status', encoding='ascii'):\n"
            " if line.startswith(('CapEff:','CapPrm:','CapBnd:','CapInh:','CapAmb:','NoNewPrivs:')): d[line.split(':',1)[0]]=line.split(':',1)[1].strip()\n"
            "d['apparmor_current']=open('/proc/self/attr/current', encoding='ascii').read().strip()\n"
            "print(json.dumps(d))\n"
        )
        proc = self.command("user namespace capability and identity map probe", self.base_args(self.stage_copy, namespaces=("user",)) + ["/usr/bin/python3", "-c", cap_probe])
        if proc.returncode == 0:
            try:
                report = json.loads(proc.stdout.strip().splitlines()[-1])
                uid_rows = [list(map(int, line.split())) for line in report["uid_map"]]
                gid_rows = [list(map(int, line.split())) for line in report["gid_map"]]
                # /proc/*_map columns are (parent-namespace ID,
                # child-namespace ID, length), so the caller maps to inner 0.
                uid_ok = len(uid_rows) == 1 and uid_rows[0] == [os.getuid(), 0, 1]
                gid_ok = len(gid_rows) == 1 and gid_rows[0] == [os.getgid(), 0, 1]
                capability_fields = ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb")
                capabilities_zero = all(report.get(key) == "0000000000000000" for key in capability_fields)
                no_new_privs = report.get("NoNewPrivs") == "1"
                expected_profile = report.get("apparmor_current", "").startswith("bwrap//&unpriv_bwrap (enforce)")
                self.check(
                    "namespace identity mapping and capability scope recorded",
                    uid_ok and gid_ok,
                    f"uid_map={report['uid_map']}, gid_map={report['gid_map']}, CapEff={report.get('CapEff')}, CapBnd={report.get('CapBnd')}",
                )
                self.check(
                    "Bubblewrap child uses the distro profile without capabilities",
                    expected_profile and capabilities_zero and no_new_privs,
                    f"AppArmor={report.get('apparmor_current')!r}; "
                    + ", ".join(f"{key}={report.get(key)!r}" for key in (*capability_fields, "NoNewPrivs")),
                )
            except (ValueError, KeyError, IndexError) as exc:
                self.check("namespace identity mapping and capability scope recorded", False, f"could not parse child report: {exc}; stdout={proc.stdout!r}")
        else:
            self.check("namespace identity mapping and capability scope recorded", False, f"returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")
        return combined_ok

    def filesystem_tests(self) -> None:
        read_probe = "from pathlib import Path; raise SystemExit(0 if Path('/workspace/src/readonly.txt').read_text() == 'read-only sibling\\n' else 41)"
        proc = self.py(read_probe)
        self.check("authorized staged read succeeds", proc.returncode == 0, f"returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")

        proc = self.py("from pathlib import Path; Path('/workspace/src/allowed.txt').write_text('authorized exact-file write\\n')", writable_file=self.exact_file)
        self.check("exact-file write grant succeeds", proc.returncode == 0 and self.exact_file.read_text() == "authorized exact-file write\n", f"returncode={proc.returncode}; stage bytes={self.exact_file.read_text()!r}")

        denied_write = (
            "from pathlib import Path\n"
            "try: Path('/workspace/src/readonly.txt').write_text('must not happen')\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(42)\n"
        )
        before = (self.stage_copy / "src" / "readonly.txt").read_text()
        proc = self.py(denied_write, writable_file=self.exact_file)
        after = (self.stage_copy / "src" / "readonly.txt").read_text()
        self.check("unauthorized sibling write denied", proc.returncode == 0 and after == before, f"returncode={proc.returncode}; host-inspected sibling unchanged={after == before}")

        create_probe = (
            "from pathlib import Path\n"
            "try: Path('/workspace/src/new-file.txt').write_text('must not happen')\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(43)\n"
        )
        proc = self.py(create_probe, writable_file=self.exact_file)
        self.check("exact-file grant does not grant parent-directory creation", proc.returncode == 0 and not (self.stage_copy / "src" / "new-file.txt").exists(), f"returncode={proc.returncode}")

        operation_probe = (
            "import os\n"
            "p='/workspace/out'\n"
            "open(p+'/created.txt','w').write('created\\n')\n"
            "open(p+'/existing.txt','w').write('modified\\n')\n"
            "os.rename(p+'/created.txt',p+'/renamed.txt')\n"
            "os.unlink(p+'/renamed.txt')\n"
            "os.replace(p+'/replacement.tmp',p+'/atomic.txt') if os.path.exists(p+'/replacement.tmp') else None\n"
        )
        # Atomic replacement gets an explicit temporary file in the same
        # writable directory so that rename semantics are tested positively.
        (self.stage_copy / "out" / "replacement.tmp").write_text("replacement\n", encoding="utf-8")
        proc = self.py(operation_probe, writable_dirs=(self.out_dir,))
        host_ok = (
            not (self.out_dir / "created.txt").exists()
            and (self.out_dir / "existing.txt").read_text() == "modified\n"
            and (self.out_dir / "atomic.txt").read_text() == "replacement\n"
            and not (self.out_dir / "replacement.tmp").exists()
        )
        self.check("writable directory create/modify/delete/rename/atomic-replace", proc.returncode == 0 and host_ok, f"returncode={proc.returncode}; controller filesystem checks={host_ok}")

        before_exact = self.exact_file.read_text()
        replace_probe = (
            "import os\n"
            "p='/workspace/src/allowed.txt'\n"
            "for operation in (lambda: os.unlink(p), lambda: os.rename(p,p+'.moved'), lambda: os.replace('/workspace/out/replacement-for-exact.tmp',p)):\n"
            " try: operation()\n"
            " except OSError: continue\n"
            " raise SystemExit(44)\n"
            "raise SystemExit(0)\n"
        )
        (self.stage_copy / "out" / "replacement-for-exact.tmp").write_text("candidate\n", encoding="utf-8")
        proc = self.py(replace_probe, writable_file=self.exact_file, writable_dirs=(self.out_dir,))
        host_ok = self.exact_file.read_text() == before_exact
        self.check("exact-file grant blocks unlink/rename/atomic replacement", proc.returncode == 0 and host_ok, f"returncode={proc.returncode}; exact file unchanged after denied namespace operations={host_ok}")

        nested_file = self.stage_copy / "out" / "locked.txt"
        nested_probe = (
            "from pathlib import Path\n"
            "Path('/workspace/out/allowed-neighbor.txt').write_text('allowed')\n"
            "try: Path('/workspace/out/locked.txt').write_text('must not happen')\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(45)\n"
        )
        proc = self.py(nested_probe, writable_dirs=(self.out_dir,), nested_readonly_file=nested_file)
        nested_ok = nested_file.read_text() == "nested readonly file\n" and (self.out_dir / "allowed-neighbor.txt").read_text() == "allowed"
        self.check("nested read-only file mount takes precedence over writable directory", proc.returncode == 0 and nested_ok, f"returncode={proc.returncode}; host-inspected nested and neighbor files={nested_ok}")

        symlink_probe = (
            "from pathlib import Path\n"
            "paths=['/workspace/links/absolute-escape.txt','/workspace/links/chain-a.txt','/workspace/links/chain-b.txt']\n"
            "for p in paths:\n"
            " try: Path(p).read_text()\n"
            " except OSError: continue\n"
            " raise SystemExit(46)\n"
            "raise SystemExit(0)\n"
        )
        proc = self.py(symlink_probe)
        self.check("absolute symlink and symlink-chain escape cannot reach host canary", proc.returncode == 0 and SYNTHETIC not in proc.stdout, f"returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")

        traversal_probe = (
            "import os\n"
            f"p={str(self.host_canary)!r}\n"
            "try: open(p).read()\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(47)\n"
        )
        proc = self.py(traversal_probe)
        self.check("absolute host-path traversal cannot reach synthetic canary", proc.returncode == 0, f"returncode={proc.returncode}")

        relative_target = "/workspace/../../" + str(self.host_canary).lstrip("/")
        relative_probe = (
            "from pathlib import Path\n"
            f"p=Path({relative_target!r})\n"
            "try: p.read_bytes()\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(61)\n"
        )
        proc = self.py(relative_probe)
        self.check("relative parent traversal remains inside sandbox root", proc.returncode == 0, f"tried sandbox path={relative_target}; returncode={proc.returncode}")

        alias_probe = "from pathlib import Path; raise SystemExit(0 if Path('/workspace/links/hardlink-alias.txt').read_text().strip() == " + repr(SYNTHETIC) + " else 48)"
        proc = self.command("raw-bind hard-link alias observation", self.base_args(self.stage) + ["/usr/bin/python3", "-c", alias_probe])
        self.check("raw bind exposes contents already hard-linked into the stage (expected observation)", proc.returncode == 0, f"returncode={proc.returncode}; demonstrates Bubblewrap cannot remove source-tree hard-link content")

        raw_alias = self.stage / "links" / "hardlink-alias.txt"
        raw_write = "from pathlib import Path; Path('/workspace/links/hardlink-alias.txt').write_text('raw bind changed host inode\\n')"
        raw_proc = self.command(
            "raw-stage exact-file mount hard-link alias write observation",
            self.base_args(self.stage, writable_file=raw_alias) + ["/usr/bin/python3", "-c", raw_write],
        )
        raw_alias_mutated_host = self.host_canary.read_text().strip() == "raw bind changed host inode"
        # Restore only this synthetic fixture so later checks have a stable
        # expected canary value.
        self.host_canary.write_text(SYNTHETIC + "\n", encoding="utf-8")
        self.check("raw-stage exact-file grant follows a hard link to its external synthetic inode (expected hazard)", raw_proc.returncode == 0 and raw_alias_mutated_host, f"returncode={raw_proc.returncode}; external synthetic inode changed through alias={raw_alias_mutated_host}")

        copy_inode_ok = os.stat(self.stage_copy / "links" / "hardlink-alias.txt").st_ino != os.stat(self.host_canary).st_ino
        copied_alias = self.stage_copy / "links" / "hardlink-alias.txt"
        copy_write = "from pathlib import Path; Path('/workspace/links/hardlink-alias.txt').write_text('staged copy only\\n')"
        proc = self.command(
            "copied-stage hard-link write isolation",
            self.base_args(self.stage_copy, writable_file=copied_alias)
            + ["/usr/bin/python3", "-c", copy_write],
        )
        # NOTE: this path uses the exact-file mount construction directly to
        # avoid granting the containing links directory write access.
        host_untouched = self.host_canary.read_text().strip() == SYNTHETIC
        self.check("copied stage breaks a synthetic external hard-link write alias", proc.returncode == 0 and copy_inode_ok and host_untouched, f"returncode={proc.returncode}; inode separated={copy_inode_ok}; external canary unchanged={host_untouched}")

        hardlink_probe = (
            "import os\n"
            "try: os.link('/workspace/src/readonly.txt','/workspace/out/from-readonly.txt')\n"
            "except OSError as e: raise SystemExit(0 if e.errno in (18,1,13,30) else 49)\n"
            "raise SystemExit(50)\n"
        )
        proc = self.py(hardlink_probe, writable_dirs=(self.out_dir,))
        self.check("hard link cannot cross read-only and writable bind mounts", proc.returncode == 0 and not (self.out_dir / "from-readonly.txt").exists(), f"returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")

        private_tmp_path = self.host / "private-tmp-canary.txt"
        temp_probe = (
            "from pathlib import Path\n"
            f"p=Path({str(private_tmp_path)!r})\n"
            "p.parent.mkdir(parents=True,exist_ok=True); p.write_text('private tmp')\n"
            "raise SystemExit(0 if p.read_text() == 'private tmp' else 51)\n"
        )
        proc = self.py(temp_probe)
        self.check("private tmpfs is writable and host /tmp remains unchanged", proc.returncode == 0 and not private_tmp_path.exists(), f"returncode={proc.returncode}; corresponding host path absent={not private_tmp_path.exists()}")

        original_hash_before = (self.original / "project.txt").read_bytes()
        original_probe = (
            "from pathlib import Path\n"
            f"p=Path({str(self.original / 'project.txt')!r})\n"
            "try: p.write_text('changed')\n"
            "except OSError: raise SystemExit(0)\n"
            "raise SystemExit(52)\n"
        )
        proc = self.py(original_probe)
        original_unchanged = (self.original / "project.txt").read_bytes() == original_hash_before
        self.check("original checkout path is absent and unchanged", proc.returncode == 0 and original_unchanged, f"returncode={proc.returncode}; controller hash unchanged={original_unchanged}")

        canary_before = self.host_canary.read_bytes()
        credential_probe = (
            "from pathlib import Path\n"
            f"paths={[str(self.host_canary), str(self.host / 'home' / '.ssh' / 'id_ed25519')]!r}\n"
            "for p in paths:\n"
            " try: Path(p).read_bytes()\n"
            " except OSError: continue\n"
            " raise SystemExit(53)\n"
            "raise SystemExit(0)\n"
        )
        proc = self.py(credential_probe)
        canary_unchanged = self.host_canary.read_bytes() == canary_before
        self.check("host-only synthetic credential and home paths inaccessible", proc.returncode == 0 and canary_unchanged, f"returncode={proc.returncode}; controller canary unchanged={canary_unchanged}")

    def environment_and_fd_tests(self) -> None:
        env_probe = "import os; raise SystemExit(0 if 'AUTOCAGE_M0_SENTINEL' not in os.environ else 54)"
        proc = self.command(
            "synthetic inherited environment scrub",
            self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", env_probe],
            extra_env={"AUTOCAGE_M0_SENTINEL": SYNTHETIC},
        )
        self.check("--clearenv removes inherited synthetic sentinel", proc.returncode == 0, f"returncode={proc.returncode}; no host environment values are recorded")

        fd_path = self.host / "fd-canary.txt"
        fd_path.write_text(SYNTHETIC + "\n", encoding="utf-8")
        with fd_path.open("rb") as canary_fd:
            os.set_inheritable(canary_fd.fileno(), True)
            controller_positive = os.pread(canary_fd.fileno(), 4096, 0).decode("utf-8").strip() == SYNTHETIC
            fd_probe = (
                "import os, sys\n"
                "try: data=os.pread(int(sys.argv[1]),4096,0)\n"
                "except OSError: raise SystemExit(0)\n"
                f"raise SystemExit(55 if {SYNTHETIC!r}.encode() in data else 0)\n"
            )
            args = self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", fd_probe, str(canary_fd.fileno())]

            # This is a deliberate hazard control: Bubblewrap does not close
            # arbitrary descriptors supplied to it. The production launcher
            # must close all unapproved descriptors before execing Bubblewrap.
            leaked = self.command("explicit inherited-FD hazard control", args, pass_fds=(canary_fd.fileno(),))
            self.check(
                "trusted controller can read synthetic FD canary (positive control)",
                controller_positive,
                f"controller read synthetic canary={controller_positive}",
            )
            self.check(
                "Bubblewrap preserves an explicitly inherited FD (documented launcher requirement)",
                leaked.returncode == 55,
                f"returncode={leaked.returncode}; expected 55 only when child reads synthetic canary; stderr={leaked.stderr.strip()!r}",
            )

            # subprocess.run closes all non-stdio descriptors by default when
            # pass_fds is empty. This validates the launch discipline needed
            # by AutoCage while preserving the ordinary-user execution path.
            sanitized = self.command("unapproved inherited-FD blocked by launcher close_fds", args)
        self.check(
            "launcher closes unapproved host canary FD before Bubblewrap",
            sanitized.returncode == 0,
            f"returncode={sanitized.returncode}; stderr={sanitized.stderr.strip()!r}",
        )

    def listener_tests(self) -> None:
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.sendall(b"M0-SYNTHETIC-LISTENER\n")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        listener = Server(("0.0.0.0", 0), Handler)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        _, port = listener.server_address
        host_ip = self.default_interface_ipv4()
        try:
            loopback_ok = self.listener_positive("127.0.0.1", port)
            self.check("VM loopback listener positive control", loopback_ok, f"127.0.0.1:{port} accepted controller connection={loopback_ok}")
            if host_ip is not None:
                interface_ok = self.listener_positive(host_ip, port)
                self.check("VM interface listener positive control", interface_ok, f"{host_ip}:{port} accepted controller connection={interface_ok}")
            else:
                self.note("VM interface listener positive control", "BLOCKED", "no guest interface IPv4 address was available for a synthetic host-service listener")

            targets = [("127.0.0.1", port)]
            if host_ip is not None:
                targets.append((host_ip, port))
            child_probe = (
                "import socket,sys\n"
                f"s=socket.socket(); s.settimeout(.3); rc=s.connect_ex(('127.0.0.1',{port}))\n"
                "raise SystemExit(0 if rc != 0 else 57)\n"
            )
            network_probe = (
                "import socket, subprocess\n"
                f"targets={targets!r}\n"
                "for host,port in targets:\n"
                " s=socket.socket(); s.settimeout(.3)\n"
                " try: rc=s.connect_ex((host,port))\n"
                " finally: s.close()\n"
                " if rc == 0: raise SystemExit(56)\n"
                f"child={child_probe!r}\n"
                "rc=subprocess.run(['/usr/bin/python3','-c',child]).returncode\n"
                "raise SystemExit(rc)\n"
            )
            proc = self.command("network isolation and child inheritance", self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", network_probe])
            self.check("private network namespace blocks host listeners for process and child", proc.returncode == 0, f"tested targets={targets}; returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")

            if host_ip is None:
                self.note("outbound/default-gateway network isolation", "BLOCKED", "no guest interface IPv4 address was available for a synthetic guest-host service")
            else:
                gateway_probe = (
                    "import socket,sys\n"
                    f"s=socket.socket(); s.settimeout(.3); rc=s.connect_ex(({host_ip!r},{port}))\n"
                    "raise SystemExit(0 if rc != 0 else 58)\n"
                )
                proc = self.command("network namespace cannot reach guest interface synthetic listener", self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", gateway_probe])
                self.check("network namespace blocks connection to VM guest interface listener", proc.returncode == 0, f"guest_ip={host_ip}; returncode={proc.returncode}; stderr={proc.stderr.strip()!r}")

            remote_probe = (
                "import socket,sys\n"
                "s=socket.socket(); s.settimeout(.3); rc=s.connect_ex(('192.0.2.1',9))\n"
                "raise SystemExit(0 if rc != 0 else 59)\n"
            )
            proc = self.command("network namespace has no usable route to TEST-NET-1", self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", remote_probe])
            self.check("no outbound connection to reserved TEST-NET address", proc.returncode == 0, f"returncode={proc.returncode}; no public service was contacted")
        finally:
            listener.shutdown()
            listener.server_close()
            thread.join(timeout=1)

        socket_path = self.host / "host-only.sock"
        unix_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_server.bind(str(socket_path))
        unix_server.listen(1)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as positive:
                positive.settimeout(1)
                positive.connect(str(socket_path))
            self.check("host Unix socket positive control", True, "controller connected to synthetic host-only Unix socket")
            unix_probe = (
                "import socket,sys\n"
                f"s=socket.socket(socket.AF_UNIX); rc=s.connect_ex({str(socket_path)!r})\n"
                "raise SystemExit(0 if rc != 0 else 60)\n"
            )
            proc = self.command("host Unix socket inaccessible inside sandbox", self.base_args(self.stage_copy) + ["/usr/bin/python3", "-c", unix_probe])
            self.check("host Unix socket is not mounted or reachable", proc.returncode == 0, f"returncode={proc.returncode}")
        finally:
            unix_server.close()

    @staticmethod
    def listener_positive(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=1) as client:
                return client.recv(64) == b"M0-SYNTHETIC-LISTENER\n"
        except OSError:
            return False

    @staticmethod
    def default_interface_ipv4() -> str | None:
        try:
            lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
            route_interface = None
            for line in lines:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    route_interface = fields[0]
                    break
            if route_interface is None:
                return None
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                request = struct.pack("256s", route_interface.encode("ascii")[:15])
                response = fcntl.ioctl(probe.fileno(), 0x8915, request)
            return socket.inet_ntoa(response[20:24])
        except (OSError, ValueError, IndexError):
            return None

    def timeout_test(self) -> None:
        code = "import subprocess,time; subprocess.Popen(['/usr/bin/sleep','20']); print('CHILD_STARTED',flush=True); time.sleep(20)"
        argv = [self.bwrap, *self.base_args(self.stage_copy), "/usr/bin/python3", "-c", code]
        self.commands.append({"test": "timeout and process group cleanup", "argv": argv, "timeout_seconds": 0.4, "termination": "SIGTERM then SIGKILL to the new process group"})
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        started = False
        ready, _, _ = select.select([process.stdout], [], [], 5)
        if ready and process.stdout is not None:
            started = process.stdout.readline().strip() == "CHILD_STARTED"
        time.sleep(0.1)
        timed_out = False
        try:
            process.communicate(timeout=0.4)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=1)
        remaining = self.live_processes_in_group(process.pid)
        self.check("timeout terminates a started sandbox command and live descendants", started and timed_out and process.returncode is not None and not remaining, f"child_started={started}; timed_out={timed_out}; leader_returncode={process.returncode}; live_group_pids={remaining}")

    @staticmethod
    def live_processes_in_group(pgid: int) -> list[int]:
        survivors: list[int] = []
        for entry in Path("/proc").glob("[0-9]*/stat"):
            try:
                raw = entry.read_text(encoding="ascii")
                tail = raw[raw.rfind(")") + 2 :].split()
                state, group = tail[0], int(tail[2])
                if group == pgid and state != "Z":
                    survivors.append(int(entry.parent.name))
            except (OSError, ValueError, IndexError):
                continue
        return survivors

    def python_runtime_test(self) -> None:
        project = "/workspace/python-project"
        env_args = [
            "--setenv",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            "1",
            "--setenv",
            "PYTHONPATH",
            f"{project}/src",
        ]
        base = self.base_args(self.stage_copy)
        # Place the explicit Python import configuration before `--`.
        separator = base.index("--")
        base[separator:separator] = env_args
        command = base + ["/usr/bin/pytest", "-p", "no:cacheprovider", "-q", f"{project}/tests"]
        proc = self.command("minimal read-only runtime plus private tmp pytest fixture", command, timeout=30)
        self.check("representative Python/pytest project under read-only runtime and private tmp", proc.returncode == 0 and "2 passed" in proc.stdout, f"returncode={proc.returncode}; stdout={proc.stdout.strip()!r}; stderr={proc.stderr.strip()!r}; runtime mounts=/usr (read-only), /etc (read-only), /bin,/sbin,/lib,/lib64 aliases, minimal /dev, private /proc and /tmp")

        minimal_base = self.base_args(self.stage_copy, include_etc=False)
        sep = minimal_base.index("--")
        minimal_base[sep:sep] = env_args
        minimal_command = minimal_base + ["/usr/bin/pytest", "-p", "no:cacheprovider", "-q", f"{project}/tests"]
        proc = self.command("pytest without /etc runtime mount", minimal_command, timeout=30)
        self.note("Python/pytest with /etc omitted", "PASS" if proc.returncode == 0 and "2 passed" in proc.stdout else "FAIL", f"returncode={proc.returncode}; stdout={proc.stdout.strip()!r}; stderr={proc.stderr.strip()!r}")

    def write_results(self, environment: dict[str, Any], verdict: str, limitations: list[str]) -> None:
        payload = {
            "schema_version": 1,
            "experiment": "AutoCage M0 Linux feasibility",
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "environment": environment,
            "verdict": verdict,
            "tests": self.tests,
            "commands": self.commands,
            "limitations": limitations,
        }
        self.results_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.results_path.with_suffix(self.results_path.suffix + ".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, self.results_path)


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def read_optional(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="ascii").strip()
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write structured JSON evidence to this path")
    parser.add_argument("--keep-lab", action="store_true", help="retain synthetic temporary fixtures for post-run inspection")
    args = parser.parse_args()
    timestamp = dt.datetime.now(dt.timezone.utc)
    default_output = Path("results") / f"m0-{timestamp.strftime('%Y%m%dT%H%M%SZ')}-{platform.machine()}.json"
    output = args.output or default_output
    os_release = read_os_release()
    bwrap = shutil.which("bwrap")
    version = None
    version_error = None
    if bwrap:
        try:
            version_run = subprocess.run([bwrap, "--version"], capture_output=True, text=True, timeout=5, check=False)
            version = version_run.stdout.strip()
            if version_run.returncode != 0:
                version_error = version_run.stderr.strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            version_error = repr(exc)
    environment = {
        "os": platform.system(),
        "distribution": os_release.get("PRETTY_NAME"),
        "distribution_id": os_release.get("ID"),
        "distribution_version": os_release.get("VERSION_ID"),
        "architecture": platform.machine(),
        "kernel": platform.release(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "bubblewrap_path": bwrap,
        "bubblewrap_version": version,
        "bubblewrap_version_error": version_error,
        "python": platform.python_version(),
        "hostname": platform.node(),
        "nested_user_namespace_settings": {
            "/proc/sys/user/max_user_namespaces": read_optional("/proc/sys/user/max_user_namespaces"),
            "/proc/sys/kernel/unprivileged_userns_clone": read_optional("/proc/sys/kernel/unprivileged_userns_clone"),
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": read_optional("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        },
        "apparmor": {
            "enabled": read_optional("/sys/module/apparmor/parameters/enabled"),
            "restrict_unprivileged_userns": read_optional("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
            "current_controller_profile": read_optional("/proc/self/attr/current"),
            "profile_sha256": None,
            "package_versions": {},
            "bubblewrap_profile_files_present": [
                path
                for path in (
                    "/etc/apparmor.d/bwrap",
                    "/etc/apparmor.d/bwrap-userns-restrict",
                    "/usr/share/apparmor/extra-profiles/bwrap-userns-restrict",
                )
                if Path(path).exists()
            ],
        },
    }
    profile_path = Path("/usr/share/apparmor/extra-profiles/bwrap-userns-restrict")
    if profile_path.is_file():
        environment["apparmor"]["profile_sha256"] = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    packages = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}=${Version}\\n", "bubblewrap", "apparmor-profiles", "apparmor-utils"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if packages.returncode == 0:
        environment["apparmor"]["package_versions"] = dict(
            line.split("=", 1) for line in packages.stdout.splitlines() if "=" in line
        )

    blockers: list[str] = []
    if platform.system() != "Linux":
        blockers.append("M0 enforcement tests require Linux")
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        blockers.append("target distribution is not Ubuntu 24.04")
    if platform.machine() not in {"aarch64", "arm64"}:
        blockers.append("target architecture is not ARM64")
    try:
        kernel_version = tuple(int(part) for part in platform.release().split("-", 1)[0].split(".")[:2])
        if kernel_version < (6, 8):
            blockers.append("kernel is older than 6.8")
    except ValueError:
        blockers.append("kernel version could not be parsed")
    if os.geteuid() == 0:
        blockers.append("controller is root; unprivileged namespace behavior would not be validated")
    if not bwrap or not version or version_error:
        blockers.append("Bubblewrap is unavailable or its version could not be read")
    if read_optional("/sys/module/apparmor/parameters/enabled") != "Y":
        blockers.append("AppArmor is not enabled; the approved Ubuntu Bubblewrap profile cannot be validated")
    if read_optional("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") != "1":
        blockers.append("kernel.apparmor_restrict_unprivileged_userns is not 1; M0 requires the global restriction to remain enabled")
    if blockers:
        controller = Controller(Path.cwd(), bwrap or "bwrap", output)
        controller.note("Linux target and required tools preflight", "BLOCKED", "; ".join(blockers))
        controller.note("Bubblewrap enforcement tests", "NOT TESTED", "preflight failed; no sandbox command was invoked")
        controller.write_results(environment, "BLOCKED", ["No enforcement test ran because preflight failed."])
        print("BLOCKED: " + "; ".join(blockers), file=sys.stderr)
        return 2

    lab_path = Path(tempfile.mkdtemp(prefix="autocage-m0-"))
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "python-project"
    controller = Controller(lab_path, bwrap, output)
    limitations: list[str] = [
        "This bounded canary does not prove absence of kernel or Bubblewrap escapes.",
        "No hard aggregate CPU, memory, or process-count limit is tested or provided.",
        "The harness observes namespace-local capability bits; nonzero values are not host-namespace capabilities.",
        "No public network service is contacted; network probes use a synthetic guest listener and reserved TEST-NET address.",
    ]
    try:
        controller.prepare(fixtures)
        namespaces_ready = controller.namespace_tests()
        if not namespaces_ready:
            for suite in (
                "filesystem bind and path-edge matrix",
                "host canary, environment, and inherited-FD checks",
                "network listener and Unix socket checks",
                "timeout and descendant cleanup check",
                "Python/pytest runtime check",
            ):
                controller.note(suite, "BLOCKED", "required combined Bubblewrap namespace setup failed; no dependent probe was launched")
            verdict = "FAIL" if any(test["status"] == "FAIL" for test in controller.tests) else "BLOCKED"
            controller.write_results(environment, verdict, limitations + ["The required combined namespace preflight failed, so dependent filesystem, network, process, and Python tests were not run."])
            print(f"{verdict}: {len(controller.tests)} checks; evidence: {output}")
            print(json.dumps({status: sum(test["status"] == status for test in controller.tests) for status in ("PASS", "FAIL", "BLOCKED", "NOT TESTED")}, sort_keys=True))
            if args.keep_lab:
                print(f"synthetic lab retained: {lab_path}")
            else:
                shutil.rmtree(lab_path)
            return 1 if verdict == "FAIL" else 2
        controller.filesystem_tests()
        controller.environment_and_fd_tests()
        controller.listener_tests()
        controller.timeout_test()
        controller.python_runtime_test()
        statuses = [test["status"] for test in controller.tests]
        verdict = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses or "NOT TESTED" in statuses else "PASS"
        controller.write_results(environment, verdict, limitations)
        print(f"{verdict}: {len(controller.tests)} checks; evidence: {output}")
        print(json.dumps({status: statuses.count(status) for status in ("PASS", "FAIL", "BLOCKED", "NOT TESTED")}, sort_keys=True))
        if args.keep_lab:
            print(f"synthetic lab retained: {lab_path}")
        else:
            shutil.rmtree(lab_path)
        return 0 if verdict == "PASS" else (2 if verdict == "BLOCKED" else 1)
    except Exception as exc:  # Preserve a failing result rather than silently losing evidence.
        controller.note("harness completed without an uncaught exception", "FAIL", repr(exc))
        controller.note("remaining M0 checks", "NOT TESTED", "harness stopped at an uncaught exception")
        controller.write_results(environment, "FAIL", limitations + ["Harness exception: " + repr(exc)])
        if args.keep_lab:
            print(f"synthetic lab retained for diagnosis: {lab_path}", file=sys.stderr)
        else:
            shutil.rmtree(lab_path, ignore_errors=True)
        print(f"FAIL: unexpected harness error {exc!r}; evidence: {output}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
