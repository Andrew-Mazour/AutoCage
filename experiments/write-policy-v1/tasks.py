"""Frozen deterministic scripted tasks for write-policy experiment v1.

Agent programs and verifiers are inline Python snippets executed only by the
Bubblewrap runner. They are data for the guest-side controller, never run on
the macOS host.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Task:
    task_id: str
    family: str
    agent: str
    verify: str
    expected_effects: tuple[str, ...]
    notes: str = ""
    pytest: bool = False


def code(text: str) -> str:
    return text.strip() + "\n"


TASKS = (
    Task("T01-read-only", "read-only", code("assert 'alpha' in open('/workspace/src/a.txt').read()"), "assert open('/workspace/src/a.txt').read() == 'alpha\\n'", (), "Reads source without task modifications."),
    Task("T02-edit-one", "existing-file", code("open('/workspace/src/a.txt','w').write('changed\\n')"), "assert open('/workspace/src/a.txt').read() == 'changed\\n'", ("modify:src/a.txt",)),
    Task("T03-edit-two", "multi-file", code("open('/workspace/src/a.txt','w').write('A\\n'); open('/workspace/src/b.txt','w').write('B\\n')"), "assert open('/workspace/src/a.txt').read() == 'A\\n' and open('/workspace/src/b.txt').read() == 'B\\n'", ("modify:src/a.txt", "modify:src/b.txt")),
    Task("T04-cross-directory", "multi-directory", code("open('/workspace/src/a.txt','w').write('source\\n'); open('/workspace/lib/helper.txt','w').write('library\\n')"), "assert open('/workspace/src/a.txt').read() == 'source\\n' and open('/workspace/lib/helper.txt').read() == 'library\\n'", ("modify:src/a.txt", "modify:lib/helper.txt")),
    Task("T05-create-source", "create", code("open('/workspace/src/new_module.py','w').write('VALUE = 41\\n')"), "assert open('/workspace/src/new_module.py').read() == 'VALUE = 41\\n'", ("create:src/new_module.py",)),
    Task("T06-create-config", "create", code("open('/workspace/config/new.toml','w').write('enabled = true\\n')"), "assert open('/workspace/config/new.toml').read() == 'enabled = true\\n'", ("create:config/new.toml",)),
    Task("T07-delete", "delete", code("import os; os.unlink('/workspace/src/remove.txt')"), "assert not __import__('os').path.exists('/workspace/src/remove.txt')", ("delete:src/remove.txt",)),
    Task("T08-rename", "rename", code("import os; os.rename('/workspace/src/old.py','/workspace/src/new.py')"), "assert not __import__('os').path.exists('/workspace/src/old.py') and open('/workspace/src/new.py').read() == 'old\\n'", ("rename:src/old.py->src/new.py",)),
    Task("T09-atomic-replace", "atomic-replace", code("from pathlib import Path; import os; p=Path('/workspace/src/a.txt'); t=Path('/workspace/src/.save.tmp'); t.write_text('atomic\\n'); os.replace(t,p)"), "assert open('/workspace/src/a.txt').read() == 'atomic\\n'", ("replace:src/a.txt",)),
    Task("T10-python-pytest", "python-tests", code("from pathlib import Path; Path('/workspace/src/mathops.py').write_text('def add(a, b):\\n    return a + b\\n'); import subprocess; subprocess.run(['/usr/bin/python3','-m','pytest','-q','-p','no:cacheprovider','/workspace/tests'],check=True)"), "import subprocess; subprocess.run(['/usr/bin/pytest','-q','-p','no:cacheprovider','/workspace/tests'],check=True)", ("modify:src/mathops.py",), "Runs a real pytest suite inside both task and verifier.", True),
    Task("T11-transient-temp", "transient-write", code("from pathlib import Path; p=Path('/workspace/build/transient.tmp'); p.write_text('ephemeral'); p.unlink(); Path('/workspace/src/a.txt').write_text('kept\\n')"), "assert open('/workspace/src/a.txt').read() == 'kept\\n' and not __import__('os').path.exists('/workspace/build/transient.tmp')", ("modify:src/a.txt",), "Final manifest cannot reveal the temporary create/unlink."),
    Task("T12-deep-edit", "nested-path", code("open('/workspace/src/pkg/deep/module.txt','w').write('nested\\n')"), "assert open('/workspace/src/pkg/deep/module.txt').read() == 'nested\\n'", ("modify:src/pkg/deep/module.txt",)),
    Task("T13-generated-output", "generated-output", code("open('/workspace/build/generated.json','w').write('{\\\"ok\\\":true}\\n')"), "assert open('/workspace/build/generated.json').read() == '{\\\"ok\\\":true}\\n'", ("create:build/generated.json",)),
    Task("T14-joint-permissions", "joint-permission", code("open('/workspace/src/a.txt','w').write('left\\n'); open('/workspace/src/b.txt','w').write('right\\n')"), "assert open('/workspace/src/a.txt').read() == 'left\\n' and open('/workspace/src/b.txt').read() == 'right\\n'", ("modify:src/a.txt", "modify:src/b.txt"), "Both grants are required jointly."),
    Task("T15-conditional-path", "path-dependent", code("from pathlib import Path; p=Path('/workspace/src/preferred.txt');\ntry:\n    with p.open('a') as f: f.write('preferred\\n')\nexcept OSError:\n    Path('/workspace/src/fallback.txt').write_text('fallback\\n')"), "from pathlib import Path; assert Path('/workspace/src/preferred.txt').read_text().endswith('preferred\\n') or Path('/workspace/src/fallback.txt').read_text() == 'fallback\\n'", ("modify:src/preferred.txt",), "Removing the preferred grant changes the agent's branch."),
    Task("T16-transient-cache", "transient-cache", code("from pathlib import Path; d=Path('/workspace/cache/job'); d.mkdir(); (d/'state').write_text('temp'); (d/'state').unlink(); d.rmdir(); Path('/workspace/src/b.txt').write_text('cache task\\n')"), "assert open('/workspace/src/b.txt').read() == 'cache task\\n' and not __import__('os').path.exists('/workspace/cache/job')", ("modify:src/b.txt",), "Nested temporary directory creation and removal."),
    Task("T17-create-nested-tree", "nested-create", code("from pathlib import Path; p=Path('/workspace/src/generated/sub'); p.mkdir(parents=True); (p/'code.py').write_text('VALUE=7\\n')"), "assert open('/workspace/src/generated/sub/code.py').read() == 'VALUE=7\\n'", ("create:src/generated/sub/code.py",)),
    Task("T18-root-entry-create", "root-entry", code("open('/workspace/root-output.txt','w').write('root\\n')"), "assert open('/workspace/root-output.txt').read() == 'root\\n'", ("create:root-output.txt",), "Root-level entry creation requires a root recursive grant."),
    Task("T19-verifier-tamper-attempt", "verifier-tamper", code("from pathlib import Path; Path('/workspace/tests/guard.py').write_text('raise SystemExit(89)'); Path('/workspace/src/a.txt').write_text('legitimate\\n')"), "assert open('/workspace/tests/guard.py').read() == 'TRUSTED-VERIFIER-GUARD\\n' and open('/workspace/src/a.txt').read() == 'legitimate\\n'", ("modify:src/a.txt", "attempt:tests/guard.py"), "Fixed verifier input is taken from the pre-agent baseline snapshot.", False),
    Task("T20-incomplete-verifier", "weak-verifier", code("open('/workspace/src/wrong.txt','w').write('incorrect result')"), "assert __import__('os').path.isfile('/workspace/src/wrong.txt')", ("create:src/wrong.txt",), "Intentionally weak verifier demonstrates that pass is not correctness proof."),
    Task("T21-high-impact-file", "high-impact", code("open('/workspace/.github/workflows/ci.yml','w').write('name: changed\\n')"), "assert open('/workspace/.github/workflows/ci.yml').read() == 'name: changed\\n'", ("modify:.github/workflows/ci.yml",)),
    Task("T22-root-atomic-package", "high-impact-root", code("from pathlib import Path; import os; p=Path('/workspace/package.json'); t=Path('/workspace/.package.tmp'); t.write_text('{\\\"version\\\":\\\"2\\\"}\\n'); os.replace(t,p)"), "assert open('/workspace/package.json').read() == '{\\\"version\\\":\\\"2\\\"}\\n'", ("replace:package.json",), "Atomic replacement at root forces namespace write at the root."),
)


COMMON_FILES = {
    "README.md": "AutoCage synthetic task repository\n",
    "oracle.txt": "TRUSTED-ORACLE-v1\n",
    "src/a.txt": "alpha\n",
    "src/b.txt": "bravo\n",
    "src/remove.txt": "remove me\n",
    "src/old.py": "old\n",
    "src/pkg/deep/module.txt": "module-before\n",
    "src/preferred.txt": "preferred-before\n",
    "src/fallback.txt": "fallback-before\n",
    "lib/helper.txt": "helper-before\n",
    "config/app.toml": "enabled = false\n",
    "build/seed.txt": "generated seed\n",
    "cache/seed.txt": "cache seed\n",
    "docs/guide.md": "documentation\n",
    ".github/workflows/ci.yml": "name: original\n",
    "package.json": "{\"version\":\"1\"}\n",
    "tests/guard.py": "TRUSTED-VERIFIER-GUARD\n",
    "tests/test_mathops.py": "import sys\nsys.path.insert(0, '/workspace/src')\nfrom mathops import add\ndef test_add():\n    assert add(2, 3) == 5\n",
    "src/mathops.py": "def add(a, b):\n    return a - b\n",
}

EMPTY_DIRS = ("src/empty", "build/empty", "cache/empty", "docs/reference")
