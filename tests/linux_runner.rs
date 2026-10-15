use serde_json::Value;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_autocage"))
}

fn temp_root(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "autocage-m1-{label}-{}-{stamp}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create integration root");
    root
}

fn run_recorded(
    workspace: &Path,
    run_dir: &Path,
    agent: &str,
    verifier: &str,
) -> std::process::Output {
    prepare_recorded_verifier_input(workspace);
    let verifier = guard_verifier_input(verifier);
    Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/python3",
            "--verify-readonly",
            ".autocage-verifier",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--",
            "/usr/bin/python3",
            "-c",
            agent,
        ])
        .output()
        .expect("start recorded sandbox run")
}

fn tune_recorded(
    workspace: &Path,
    run_dir: &Path,
    agent: &str,
    verifier: &str,
) -> std::process::Output {
    let verifier = guard_verifier_input(verifier);
    Command::new(binary())
        .args([
            "tune",
            run_dir.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--agent-command",
            "/usr/bin/python3",
            "--agent-arg",
            "-c",
            "--agent-arg",
            agent,
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--max-replays",
            "4",
        ])
        .output()
        .expect("start policy tune")
}

fn prepare_recorded_verifier_input(workspace: &Path) {
    let root = workspace.join(".autocage-verifier");
    fs::create_dir_all(&root).expect("create immutable verifier input root");
    fs::write(
        root.join("contract-input.txt"),
        "AUTOCAGE-VERIFIER-INPUT-v1\n",
    )
    .expect("write immutable verifier input");
}

fn guard_verifier_input(verifier: &str) -> String {
    format!(
        "from pathlib import Path; assert Path('/workspace/.autocage-verifier/contract-input.txt').read_text() == 'AUTOCAGE-VERIFIER-INPUT-v1\\n'\n{verifier}"
    )
}

#[test]
fn check_runs_the_required_fail_closed_namespace_probe() {
    let result = Command::new(binary())
        .arg("check")
        .output()
        .expect("start autocage check");
    assert!(
        result.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("preflight passed"));
}

#[test]
fn copied_workspace_runs_command_and_readonly_verifier_then_records_review_artifacts() {
    let root = temp_root("verified");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join("tests")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let test_contents = concat!(
        "from pathlib import Path\n",
        "def test_verified_workspace_content():\n",
        "    assert Path('/workspace/src/value.txt').read_text() == 'after\\n'\n",
        "def test_verifier_snapshot_is_readonly():\n",
        "    try:\n",
        "        Path(__file__).write_text('tampered\\n')\n",
        "    except OSError:\n",
        "        pass\n",
        "    else:\n",
        "        raise AssertionError('verifier snapshot allowed overwrite')\n",
        "    try:\n",
        "        Path(__file__).with_name('created-by-verifier').write_text('x')\n",
        "    except OSError:\n",
        "        pass\n",
        "    else:\n",
        "        raise AssertionError('verifier snapshot allowed directory write')\n",
    );
    fs::write(workspace.join("tests/test_value.py"), test_contents).unwrap();
    let canary = root.join("host-canary.txt");
    fs::write(&canary, "AUTOCAGE-M1-SYNTHETIC-HOST-CANARY\n").unwrap();
    let run_dir = root.join("run-output");
    let agent_script = format!(
        "import os, subprocess\n\
         from pathlib import Path\n\
         Path('/workspace/src/value.txt').write_text('after\\n')\n\
         Path('/workspace/tests/test_value.py').write_text(\"raise AssertionError('agent replaced verifier')\\n\")\n\
         try: Path({canary:?}).read_text()\n\
         except OSError: pass\n\
         else: raise SystemExit(77)\n\
         assert 'AUTOCAGE_HOST_CANARY' not in os.environ\n\
         child = \"import os,sys;\\ntry: open(sys.argv[1]).read()\\nexcept OSError: pass\\nelse: raise SystemExit(78)\\nassert 'AUTOCAGE_HOST_CANARY' not in os.environ\"\n\
         subprocess.run(['/usr/bin/python3', '-c', child, {canary:?}], check=True)\n"
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--verify-command",
            "/usr/bin/pytest",
            "--verify-arg",
            "-p",
            "--verify-arg",
            "no:cacheprovider",
            "--verify-arg",
            "-q",
            "--verify-readonly",
            "tests",
            "--",
            "/usr/bin/python3",
            "-c",
        ])
        .arg(agent_script)
        .env("AUTOCAGE_HOST_CANARY", "AUTOCAGE-SYNTHETIC-ENV-SECRET")
        .output()
        .expect("start autocage run");
    assert!(
        result.status.success(),
        "run failed (status {:?}):\nstdout:\n{}\nstderr:\n{}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("src/value.txt")).unwrap(),
        "before\n"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("tests/test_value.py")).unwrap(),
        test_contents
    );
    assert_eq!(
        fs::read_to_string(&canary).unwrap(),
        "AUTOCAGE-M1-SYNTHETIC-HOST-CANARY\n"
    );

    let staged_test = fs::read_to_string(run_dir.join("stage/tests/test_value.py")).unwrap();
    assert!(staged_test.contains("agent replaced verifier"));
    let record_path = run_dir.join("run.json");
    let record: Value = serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
    assert_eq!(record["schema_version"], 4);
    assert!(record["phase_timings"]["workspace_stage_elapsed_millis"].is_u64());
    assert!(record["phase_timings"]["agent_backend_compile_elapsed_millis"].is_u64());
    assert!(record["phase_timings"]["verifier_backend_compile_elapsed_millis"].is_u64());
    assert!(record["phase_timings"]["supervisor_elapsed_before_record_millis"].is_u64());
    assert_eq!(record["outcome"], "verified");
    assert_eq!(record["readonly_mount_canary"]["exit_code"], 0);
    assert!(record["security_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| {
            item["name"] == "readonly_mount_write_denial" && item["status"] == "passed"
        }));
    assert!(record["security_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| { item["name"] == "external_host_canary" && item["status"] == "not_tested" }));
    assert_eq!(record["verifier_readonly_paths"][0], "tests");
    assert!(record["workspace"]["changed_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "src/value.txt"));
    assert!(record["workspace"]["changed_paths"]
        .as_array()
        .unwrap()
        .iter()
        .any(|path| path == "tests/test_value.py"));
    assert_eq!(
        fs::metadata(&record_path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let patch = fs::read_to_string(run_dir.join("changes.patch")).unwrap();
    assert!(patch.contains("a/src/value.txt"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn command_timeout_is_recorded_and_returns_124() {
    let root = temp_root("timeout");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("README.md"), "synthetic\n").unwrap();
    let run_dir = root.join("run-output");
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--timeout-seconds",
            "1",
            "--",
            "/usr/bin/sleep",
            "20",
        ])
        .output()
        .expect("start timeout run");
    assert_eq!(result.status.code(), Some(124));
    let record: Value =
        serde_json::from_slice(&fs::read(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(record["outcome"], "agent_timed_out");
    assert_eq!(record["agent"]["timed_out"], true);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn network_namespace_blocks_a_live_host_loopback_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind synthetic host listener");
    let address = listener.local_addr().unwrap();
    let positive_control = TcpStream::connect(address).expect("host positive control connects");
    drop(positive_control);

    let root = temp_root("network");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let run_dir = root.join("run-output");
    let script = format!(
        "import socket,sys\ns=socket.socket()\ns.settimeout(1)\ntry: s.connect(({:?}, {}))\nexcept OSError: raise SystemExit(0)\nraise SystemExit(77)\n",
        address.ip().to_string(),
        address.port()
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--",
            "/usr/bin/python3",
            "-c",
        ])
        .arg(script)
        .output()
        .expect("start network isolation run");
    assert!(
        result.status.success(),
        "sandbox reached the host listener: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    drop(listener);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verifier_failure_is_reported_separately_from_agent_failure() {
    let root = temp_root("verifier-failure");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let run_dir = root.join("run-output");
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--verify-command",
            "/usr/bin/false",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .expect("start verifier failure run");
    assert_eq!(result.status.code(), Some(3));
    let record: Value =
        serde_json::from_slice(&fs::read(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(record["outcome"], "verifier_failed");
    assert_eq!(record["agent"]["exit_code"], 0);
    assert_eq!(record["verifier"]["exit_code"], 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn timeout_kills_a_descendant_that_started_a_new_session() {
    let root = temp_root("detached-timeout");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let run_dir = root.join("run-output");
    let marker = format!("AUTOCAGE-M1-DETACHED-{}", std::process::id());
    let child_script = format!(
        "import subprocess,time\np=subprocess.Popen(['/usr/bin/python3','-c','import time; time.sleep(30)', {:?}], start_new_session=True)\nopen('/workspace/child.pid','w').write(str(p.pid))\ntime.sleep(30)\n",
        marker
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--timeout-seconds",
            "1",
            "--",
            "/usr/bin/python3",
            "-c",
        ])
        .arg(child_script)
        .output()
        .expect("start detached timeout run");
    assert_eq!(result.status.code(), Some(124));
    assert!(
        run_dir.join("stage/child.pid").is_file(),
        "agent did not start detached child"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let found_live_child = fs::read_dir("/proc")
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .parse::<u32>()
                    .ok()
                    .map(|pid| (entry.path(), pid))
            })
            .any(|(path, _pid)| {
                let cmdline = fs::read(path.join("cmdline")).unwrap_or_default();
                if !cmdline
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
                {
                    return false;
                }
                let status = fs::read_to_string(path.join("status")).unwrap_or_default();
                !status
                    .lines()
                    .any(|line| line.starts_with("State:") && line.contains("Z (zombie)"))
            });
        if !found_live_child {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached descendant remained alive after timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exact_file_write_grant_allows_inode_writes_but_not_directory_entry_operations() {
    let root = temp_root("exact-file-policy");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/target.txt"), "before\n").unwrap();
    fs::write(workspace.join("src/sibling.txt"), "protected\n").unwrap();
    let run_dir = root.join("run-output");
    let script = concat!(
        "from pathlib import Path\nimport os, subprocess, sys\n",
        "target=Path('/workspace/src/target.txt')\n",
        "target.write_text('after\\n')\n",
        "os.chmod(target,0o600)\n",
        "for path in ['/workspace/src/sibling.txt','/workspace/src/new.txt']:\n",
        "    try: Path(path).write_text('forbidden')\n",
        "    except OSError: pass\n",
        "    else: raise SystemExit(81)\n",
        "try: target.unlink()\n",
        "except OSError: pass\n",
        "else: raise SystemExit(82)\n",
        "Path('/tmp/replacement.txt').write_text('replacement')\n",
        "try: os.replace('/tmp/replacement.txt', str(target))\n",
        "except OSError: pass\n",
        "else: raise SystemExit(83)\n",
        "child=\"from pathlib import Path\\ntry: Path('/workspace/src/sibling.txt').write_text('child')\\nexcept OSError: raise SystemExit(0)\\nraise SystemExit(84)\"\n",
        "subprocess.run(['/usr/bin/python3','-c',child],check=True)\n",
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--ceiling-file",
            "src/target.txt",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ])
        .output()
        .expect("start exact-file policy run");
    assert!(
        result.status.success(),
        "exact-file policy failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("stage/src/target.txt")).unwrap(),
        "after\n"
    );
    assert_eq!(
        fs::metadata(run_dir.join("stage/src/target.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("stage/src/sibling.txt")).unwrap(),
        "protected\n"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("src/target.txt")).unwrap(),
        "before\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recursive_directory_grant_allows_create_delete_rename_and_atomic_replace() {
    let root = temp_root("directory-policy");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/old.txt"), "old\n").unwrap();
    fs::write(workspace.join("outside.txt"), "readonly\n").unwrap();
    let run_dir = root.join("run-output");
    let script = concat!(
        "from pathlib import Path\nimport os\n",
        "root=Path('/workspace/src')\n",
        "(root/'created.txt').write_text('created')\n",
        "(root/'old.txt').rename(root/'renamed.txt')\n",
        "(root/'temp.txt').write_text('atomic')\n",
        "os.replace(root/'temp.txt', root/'renamed.txt')\n",
        "(root/'created.txt').unlink()\n",
        "try: Path('/workspace/outside.txt').write_text('forbidden')\n",
        "except OSError: pass\n",
        "else: raise SystemExit(85)\n",
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--ceiling-dir",
            "src",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ])
        .output()
        .expect("start recursive-directory policy run");
    assert!(
        result.status.success(),
        "directory policy failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("stage/src/renamed.txt")).unwrap(),
        "atomic"
    );
    assert!(!run_dir.join("stage/src/created.txt").exists());
    assert_eq!(
        fs::read_to_string(run_dir.join("stage/outside.txt")).unwrap(),
        "readonly\n"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("src/old.txt")).unwrap(),
        "old\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn explicit_read_only_policy_allows_reads_and_blocks_writes_in_children() {
    let root = temp_root("readonly-policy");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("input.txt"), "readable\n").unwrap();
    let run_dir = root.join("run-output");
    let script = concat!(
        "from pathlib import Path\nimport subprocess\n",
        "assert Path('/workspace/input.txt').read_text() == 'readable\\n'\n",
        "try: Path('/workspace/input.txt').write_text('forbidden')\n",
        "except OSError: pass\n",
        "else: raise SystemExit(86)\n",
        "child=\"from pathlib import Path\\ntry: Path('/workspace/input.txt').write_text('child')\\nexcept OSError: raise SystemExit(0)\\nraise SystemExit(87)\"\n",
        "subprocess.run(['/usr/bin/python3','-c',child],check=True)\n",
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--read-only",
            "--",
            "/usr/bin/python3",
            "-c",
            script,
        ])
        .output()
        .expect("start read-only policy run");
    assert!(
        result.status.success(),
        "read-only policy failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read_to_string(run_dir.join("stage/input.txt")).unwrap(),
        "readable\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepted_preexecution_profile_runs_readonly_and_records_the_authorized_ceiling() {
    let root = temp_root("accepted-profile");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join("tests")).unwrap();
    fs::write(workspace.join("src/value.py"), "VALUE = 1\n").unwrap();
    fs::write(
        workspace.join("pyproject.toml"),
        "[tool.pytest.ini_options]\n",
    )
    .unwrap();
    let test_source = concat!(
        "from pathlib import Path\n",
        "import pytest\n",
        "@pytest.mark.parametrize('target', [\n",
        "    '/workspace/src/value.py',\n",
        "    '/workspace/tests/test_profile.py',\n",
        "    '/workspace/pyproject.toml',\n",
        "])\n",
        "def test_profile_denies_out_of_scope_edits(target):\n",
        "    try:\n",
        "        Path(target).write_text('AUTOCAGE-PROFILE-CANARY\\n')\n",
        "    except OSError:\n",
        "        return\n",
        "    raise AssertionError(f'write unexpectedly succeeded: {target}')\n",
    );
    fs::write(workspace.join("tests/test_profile.py"), test_source).unwrap();
    let profile_path = root.join("proposal.json");
    let command = [
        "/usr/bin/python3",
        "-m",
        "pytest",
        "tests/test_profile.py",
        "-q",
        "-p",
        "no:cacheprovider",
    ];
    let proposal = Command::new(binary())
        .args([
            "propose",
            "--workspace",
            workspace.to_str().unwrap(),
            "--workflow",
            "python-test",
            "--",
        ])
        .args(command)
        .output()
        .expect("start profile suggestion");
    assert!(
        proposal.status.success(),
        "proposal failed: {}",
        String::from_utf8_lossy(&proposal.stderr)
    );
    fs::write(&profile_path, &proposal.stdout).unwrap();

    let run_dir = root.join("run-output");
    let mut runner = Command::new(binary());
    runner.args([
        "run",
        "--workspace",
        workspace.to_str().unwrap(),
        "--run-dir",
        run_dir.to_str().unwrap(),
        "--accept-proposal",
        profile_path.to_str().unwrap(),
        "--ceiling-dir",
        ".",
        "--verify-command",
        "/usr/bin/python3",
    ]);
    for argument in command.iter().skip(1) {
        runner.arg("--verify-arg").arg(argument);
    }
    runner.args(["--verify-readonly", "tests", "--", command[0]]);
    runner.args(&command[1..]);
    let result = runner.output().expect("start accepted-profile run");
    assert!(
        result.status.success(),
        "profile run failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    for (path, original) in [
        ("src/value.py", "VALUE = 1\n"),
        ("tests/test_profile.py", test_source),
        ("pyproject.toml", "[tool.pytest.ini_options]\n"),
    ] {
        assert_eq!(fs::read_to_string(workspace.join(path)).unwrap(), original);
    }
    let record: Value =
        serde_json::from_slice(&fs::read(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(record["outcome"], "verified");
    assert_eq!(
        record["policy"]["write_grants"].as_array().unwrap().len(),
        0
    );
    assert_eq!(record["authorized_ceiling"]["write_grants"][0]["path"], ".");
    assert!(record["accepted_proposal_sha256"].as_str().is_some());
    assert!(record["security_checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| {
            check["name"] == "accepted_pre_execution_profile_identity"
                && check["status"] == "passed"
        }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn accepted_profile_is_rejected_after_source_snapshot_changes() {
    let root = temp_root("stale-profile");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join("tests")).unwrap();
    fs::write(workspace.join("src/value.py"), "VALUE = 1\n").unwrap();
    fs::write(
        workspace.join("tests/test_profile.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();
    let profile_path = root.join("proposal.json");
    let command = [
        "/usr/bin/python3",
        "-m",
        "pytest",
        "tests/test_profile.py",
        "-q",
        "-p",
        "no:cacheprovider",
    ];
    let proposal = Command::new(binary())
        .args([
            "propose",
            "--workspace",
            workspace.to_str().unwrap(),
            "--workflow",
            "python-test",
            "--",
        ])
        .args(command)
        .output()
        .unwrap();
    assert!(proposal.status.success());
    fs::write(&profile_path, proposal.stdout).unwrap();
    fs::write(workspace.join("src/value.py"), "VALUE = 2\n").unwrap();

    let run_dir = root.join("run-output");
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--accept-proposal",
            profile_path.to_str().unwrap(),
            "--ceiling-dir",
            ".",
            "--",
        ])
        .args(command)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("stale, modified"));
    assert!(!run_dir.join("run.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_contract_refuses_unprotected_verifier_inputs() {
    let root = temp_root("contract-verifier-inputs");
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let run_dir = root.join("run-output");
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/true",
            "--",
            "/usr/bin/true",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("--verify-readonly root"));
    assert!(!run_dir.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn opt_in_replay_contract_runs_tune_and_records_three_fresh_validations() {
    let root = temp_root("tune-contract");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    prepare_recorded_verifier_input(&workspace);
    let verifier = guard_verifier_input(
        "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'",
    );
    let result = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/python3",
            "--verify-readonly",
            ".autocage-verifier",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--",
            "/usr/bin/python3",
            "-c",
            agent,
        ])
        .output()
        .expect("start contract-recording run");
    assert!(
        result.status.success(),
        "initial run failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::metadata(run_dir.join("contract.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );

    let tuned = Command::new(binary())
        .args([
            "tune",
            run_dir.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--agent-command",
            "/usr/bin/python3",
            "--agent-arg",
            "-c",
            "--agent-arg",
            agent,
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--max-replays",
            "4",
        ])
        .output()
        .expect("start policy tune");
    assert!(
        tuned.status.success(),
        "tune failed: {}",
        String::from_utf8_lossy(&tuned.stderr)
    );
    let optimizer: Value =
        serde_json::from_slice(&fs::read(run_dir.join("optimizer.json")).unwrap()).unwrap();
    assert_eq!(optimizer["status"], "validated");
    assert_eq!(optimizer["search_replays"], 1);
    assert_eq!(optimizer["validation_replays"], 3);
    assert_eq!(optimizer["total_replays"], 4);
    assert_eq!(
        optimizer["best_policy"]["write_grants"][0]["kind"],
        "file_contents"
    );
    assert_eq!(
        fs::read_to_string(workspace.join("src/value.txt")).unwrap(),
        "before\n"
    );
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("\"reusable_policy\": true"));
    let optimizer_path = run_dir.join("optimizer.json");
    fs::set_permissions(&optimizer_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&optimizer_path, b"{ corrupted optimizer record").unwrap();
    fs::set_permissions(&optimizer_path, fs::Permissions::from_mode(0o400)).unwrap();
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&inspected.stderr).contains("invalid persisted evidence"));
    let retried = tune_recorded(&workspace, &run_dir, agent, &verifier);
    assert_eq!(retried.status.code(), Some(2));
    for replay in fs::read_dir(run_dir.join("tuning/replays")).unwrap() {
        let replay = replay.unwrap().path();
        assert_eq!(
            fs::read_to_string(replay.join("baseline/src/value.txt")).unwrap(),
            "before\n",
            "each replay must stage the original recorded snapshot"
        );
        assert_eq!(
            fs::read_to_string(replay.join("stage/src/value.txt")).unwrap(),
            "after\n"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_and_corrupted_run_records_are_rejected() {
    let root = temp_root("missing-record");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    let verifier = "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'";
    let initial = run_recorded(&workspace, &run_dir, agent, verifier);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );

    let record_path = run_dir.join("run.json");
    let original = fs::read(&record_path).unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&record_path, b"not json").unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(2));
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&record_path, original).unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();

    fs::remove_file(&record_path).unwrap();
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(2));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn repository_policy_configuration_cannot_expand_the_cli_ceiling() {
    let root = temp_root("repo-policy");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join("protected")).unwrap();
    fs::create_dir_all(workspace.join(".autocage")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    fs::write(workspace.join("protected/guard.txt"), "protected\n").unwrap();
    fs::write(
        workspace.join(".autocage/policy.json"),
        r#"{"write":["."]}"#,
    )
    .unwrap();
    let run_dir = root.join("run-output");
    let script = "from pathlib import Path\nassert Path('/workspace/.autocage/policy.json').read_text() == '{\\\"write\\\":[\\\".\\\"]}'\nPath('/workspace/src/value.txt').write_text('after\\n')\ntry: Path('/workspace/protected/guard.txt').write_text('escaped')\nexcept OSError: pass\nelse: raise SystemExit(99)\n";
    let result = Command::new(binary())
        .args([
            "run", "--workspace", workspace.to_str().unwrap(), "--run-dir", run_dir.to_str().unwrap(),
            "--verify-command", "/usr/bin/python3", "--verify-arg", "-c",
            "--verify-arg", "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'",
            "--ceiling-file", "src/value.txt", "--", "/usr/bin/python3", "-c", script,
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let record: Value =
        serde_json::from_slice(&fs::read(run_dir.join("run.json")).unwrap()).unwrap();
    assert_eq!(
        record["policy"]["write_grants"].as_array().unwrap().len(),
        1
    );
    assert_eq!(record["policy"]["write_grants"][0]["path"], "src/value.txt");
    assert_eq!(
        fs::read_to_string(workspace.join("protected/guard.txt")).unwrap(),
        "protected\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tune_rejects_source_snapshot_drift_before_replaying() {
    let root = temp_root("tune-source-drift");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    prepare_recorded_verifier_input(&workspace);
    let verifier = guard_verifier_input(
        "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'",
    );
    let initial = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/python3",
            "--verify-readonly",
            ".autocage-verifier",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--",
            "/usr/bin/python3",
            "-c",
            agent,
        ])
        .output()
        .expect("start contract-recording run");
    assert!(
        initial.status.success(),
        "initial run failed: {}",
        String::from_utf8_lossy(&initial.stderr)
    );
    fs::write(
        workspace.join("src/value.txt"),
        "changed outside the recorded run\n",
    )
    .unwrap();
    let tuned = Command::new(binary())
        .args([
            "tune",
            run_dir.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--agent-command",
            "/usr/bin/python3",
            "--agent-arg",
            "-c",
            "--agent-arg",
            agent,
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--max-replays",
            "4",
        ])
        .output()
        .expect("start source-drift tune");
    assert_eq!(tuned.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&tuned.stderr).contains("source workspace changed"));
    assert!(!run_dir.join("tuning/replays/trial-000/run.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn tune_rejects_changed_agent_argv_without_persisting_original_values() {
    let root = temp_root("argv-identity");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    let verifier = "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'";
    let initial = run_recorded(&workspace, &run_dir, agent, verifier);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let contract = fs::read_to_string(run_dir.join("contract.json")).unwrap();
    assert!(!contract.contains("after\\n"));
    assert!(!contract.contains("Path('/workspace/src/value.txt')"));
    let changed_agent =
        "from pathlib import Path; Path('/workspace/src/value.txt').write_text('different\\n')";
    let tuned = tune_recorded(&workspace, &run_dir, changed_agent, verifier);
    assert_eq!(tuned.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&tuned.stderr).contains("agent executable or arguments differ"));
    assert!(!run_dir.join("tuning/replays/trial-000/run.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_records_and_contracts_do_not_persist_command_values_or_output() {
    let root = temp_root("record-redaction");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "unchanged\n").unwrap();
    let run_dir = root.join("run-output");
    let secret_marker = "AUTOCAGE-RECORD-SECRET-SYNTHETIC-DO-NOT-PERSIST-9d6f4a";
    let agent = format!("print({secret_marker:?})");
    let verifier = format!("print({secret_marker:?})");
    let result = run_recorded(&workspace, &run_dir, &agent, &verifier);
    assert!(
        result.status.success(),
        "sandbox run failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let mut pending = vec![run_dir.clone()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(
                    !bytes
                        .windows(secret_marker.len())
                        .any(|window| window == secret_marker.as_bytes()),
                    "secret marker persisted in {}",
                    entry.path().display()
                );
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn run_record_tampering_and_runtime_contract_changes_are_detected() {
    let root = temp_root("record-tampering");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    let verifier = "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'";
    let initial = run_recorded(&workspace, &run_dir, agent, verifier);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );

    let record_path = run_dir.join("run.json");
    let original_record = fs::read(&record_path).unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut record: Value = serde_json::from_slice(&original_record).unwrap();
    record["outcome"] = Value::String("verified".to_owned());
    fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&inspected.stderr).contains("seal mismatch"));
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&record_path, original_record).unwrap();
    fs::set_permissions(&record_path, fs::Permissions::from_mode(0o400)).unwrap();

    let contract_path = run_dir.join("contract.json");
    fs::set_permissions(&contract_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut contract: Value = serde_json::from_slice(&fs::read(&contract_path).unwrap()).unwrap();
    contract["runtime"]["bubblewrap_sha256"] = Value::String("0".repeat(64));
    fs::write(
        &contract_path,
        serde_json::to_vec_pretty(&contract).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&contract_path, fs::Permissions::from_mode(0o400)).unwrap();
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(inspected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&inspected.stderr).contains("altered"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn altered_verifier_input_invalidates_the_run_contract() {
    let root = temp_root("verifier-drift");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join("tests")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let verifier_script = "from pathlib import Path\nassert Path('/workspace/src/value.txt').read_text() == 'after\\n'\n";
    fs::write(workspace.join("tests/verify.py"), verifier_script).unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    let initial = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "tests/verify.py",
            "--verify-readonly",
            "tests",
            "--",
            "/usr/bin/python3",
            "-c",
            agent,
        ])
        .output()
        .unwrap();
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    fs::write(workspace.join("tests/verify.py"), "raise SystemExit(0)\n").unwrap();
    let tuned = Command::new(binary())
        .args([
            "tune",
            run_dir.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--agent-command",
            "/usr/bin/python3",
            "--agent-arg",
            "-c",
            "--agent-arg",
            agent,
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "tests/verify.py",
            "--max-replays",
            "4",
        ])
        .output()
        .unwrap();
    assert_eq!(tuned.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&tuned.stderr).contains("source workspace changed"));
    assert!(!run_dir.join("tuning/replays/trial-000/run.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_run_is_visible_and_recovery_forbids_policy_reuse() {
    let root = temp_root("interrupted-recovery");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    prepare_recorded_verifier_input(&workspace);
    let run_dir = root.join("run-output");
    let mut child = Command::new(binary())
        .args([
            "run",
            "--workspace",
            workspace.to_str().unwrap(),
            "--run-dir",
            run_dir.to_str().unwrap(),
            "--record-contract",
            "--verify-command",
            "/usr/bin/true",
            "--verify-readonly",
            ".autocage-verifier",
            "--",
            "/usr/bin/python3",
            "-c",
            "import time; time.sleep(60)",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !run_dir.join("lifecycle.json").exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        run_dir.join("lifecycle.json").exists(),
        "run did not persist lifecycle state"
    );
    let temp_evidence = run_dir.join(".run.json.tmp-interrupted");
    fs::write(&temp_evidence, b"partial").unwrap();
    child.kill().unwrap();
    let _ = child.wait();

    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("INCOMPLETE"));
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("\"reusable_policy\": false"));
    let recovered = Command::new(binary())
        .args(["recover", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(!temp_evidence.exists());
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("interrupted"));
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("INCOMPLETE"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_optimization_is_not_resumed_or_promoted() {
    let root = temp_root("interrupted-tune");
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::write(workspace.join("src/value.txt"), "before\n").unwrap();
    let run_dir = root.join("run-output");
    let agent = "from pathlib import Path; Path('/workspace/src/value.txt').write_text('after\\n')";
    let verifier = "from pathlib import Path; assert Path('/workspace/src/value.txt').read_text() == 'after\\n'";
    let initial = run_recorded(&workspace, &run_dir, agent, verifier);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    let verifier = guard_verifier_input(verifier);
    let mut tuner = Command::new(binary())
        .args([
            "tune",
            run_dir.to_str().unwrap(),
            "--workspace",
            workspace.to_str().unwrap(),
            "--agent-command",
            "/usr/bin/python3",
            "--agent-arg",
            "-c",
            "--agent-arg",
            agent,
            "--verify-command",
            "/usr/bin/python3",
            "--verify-arg",
            "-c",
            "--verify-arg",
            &verifier,
            "--max-replays",
            "12",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut observed_trial = false;
    while std::time::Instant::now() < deadline {
        if let Ok(state) = fs::read(run_dir.join("lifecycle.json")) {
            if let Ok(state) = serde_json::from_slice::<Value>(&state) {
                if state["phase"] == "tuning" && state["current_trial"].is_number() {
                    observed_trial = true;
                    break;
                }
            }
        }
        if tuner.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        observed_trial,
        "optimizer finished or failed before its in-progress trial was observable"
    );
    tuner.kill().unwrap();
    let _ = tuner.wait();
    let recovered = Command::new(binary())
        .args(["recover", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(!run_dir.join("optimizer.json").exists());
    let inspected = Command::new(binary())
        .args(["inspect", run_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("interrupted"));
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("reusable_policy\": false"));
    let retry = tune_recorded(&workspace, &run_dir, agent, &verifier);
    assert_eq!(retry.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&retry.stderr).contains("complete initial run"));
    fs::remove_dir_all(root).unwrap();
}
