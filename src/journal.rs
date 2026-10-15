//! Atomic evidence seals, single-writer run locks, and crash-visible lifecycle state.

use crate::contract;
use crate::error::{AutoCageError, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const STATE_SCHEMA: u32 = 1;
const SEAL_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lifecycle {
    pub schema_version: u32,
    pub phase: String,
    pub updated_unix_millis: u128,
    pub current_trial: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunSeal {
    pub schema_version: u32,
    pub contract_sha256: Option<String>,
    pub run_record_sha256: String,
    pub baseline_manifest_sha256: String,
    pub stage_manifest_sha256: String,
    pub patch_sha256: String,
    pub readonly_canary_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OptimizerSeal {
    pub schema_version: u32,
    pub contract_sha256: String,
    pub run_record_sha256: String,
    pub optimizer_sha256: String,
}

pub struct RunLock {
    _file: File,
}

#[derive(Debug)]
pub struct ValidatedRun {
    pub record: serde_json::Value,
    pub optimizer: Option<serde_json::Value>,
    pub lifecycle: Lifecycle,
    pub record_sha256: String,
    pub contract_sha256: Option<String>,
}

pub fn lock(run_dir: &Path) -> Result<RunLock> {
    let metadata = fs::symlink_metadata(run_dir)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "inspect run directory", error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(record_error(
            "run directory must be owned by the current user, private, and not a symlink",
        ));
    }
    let path = run_dir.join(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "open run lock", error))?;
    let lock_meta = file
        .metadata()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "inspect run lock", error))?;
    if !lock_meta.is_file()
        || lock_meta.uid() != unsafe { libc::geteuid() }
        || lock_meta.permissions().mode() & 0o077 != 0
    {
        return Err(record_error(
            "run lock must be a private file owned by the current user",
        ));
    }
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(record_error(
            "run directory is already being modified by another AutoCage process",
        ));
    }
    Ok(RunLock { _file: file })
}

pub fn write_lifecycle(run_dir: &Path, phase: &str, current_trial: Option<usize>) -> Result<()> {
    if ![
        "preparing",
        "agent_running",
        "verifier_running",
        "committing",
        "complete",
        "tuning",
        "tuned",
        "inconclusive",
        "interrupted",
    ]
    .contains(&phase)
    {
        return Err(record_error("invalid run lifecycle phase"));
    }
    let state = Lifecycle {
        schema_version: STATE_SCHEMA,
        phase: phase.to_owned(),
        updated_unix_millis: crate::record::now_millis(),
        current_trial,
    };
    let bytes = contract::json_bytes(&state, "serialize lifecycle state")?;
    contract::atomic_replace_private(&run_dir.join("lifecycle.json"), &bytes, 0o400)
}

pub fn write_run_seal(run_dir: &Path, contract_sha256: Option<String>) -> Result<()> {
    let record = contract::read_private_file(&run_dir.join("run.json"), "run record")?;
    let lifecycle =
        contract::read_private_file(&run_dir.join("lifecycle.json"), "lifecycle state")?;
    let lifecycle_state: Lifecycle = serde_json::from_slice(&lifecycle)
        .map_err(|error| record_error(format!("parse lifecycle state: {error}")))?;
    if lifecycle_state.phase != "complete" {
        return Err(record_error(
            "only a completed run can receive a run evidence seal",
        ));
    }
    let baseline = crate::workspace::manifest_hash(&crate::workspace::manifest_tree(
        &run_dir.join("baseline"),
    )?)?;
    let stage =
        crate::workspace::manifest_hash(&crate::workspace::manifest_tree(&run_dir.join("stage"))?)?;
    let patch = contract::hash_private_file(&run_dir.join("changes.patch"), "review patch")?;
    let seal = RunSeal {
        schema_version: SEAL_SCHEMA,
        contract_sha256,
        run_record_sha256: contract::hash_bytes(&record),
        baseline_manifest_sha256: baseline,
        stage_manifest_sha256: stage,
        patch_sha256: patch,
        readonly_canary_sha256: contract::hash_private_file(
            &run_dir.join("readonly-canary"),
            "readonly canary",
        )?,
    };
    let bytes = contract::json_bytes(&seal, "serialize run seal")?;
    contract::atomic_private_write(&run_dir.join("run.seal.json"), &bytes, 0o400)
}

pub fn write_optimizer_seal(run_dir: &Path) -> Result<()> {
    let (_loaded_contract, contract_sha256) = contract::load(run_dir)?;
    let run_record = contract::read_private_file(&run_dir.join("run.json"), "run record")?;
    let optimizer =
        contract::read_private_file(&run_dir.join("optimizer.json"), "optimizer result")?;
    let lifecycle =
        contract::read_private_file(&run_dir.join("lifecycle.json"), "lifecycle state")?;
    let lifecycle_state: Lifecycle = serde_json::from_slice(&lifecycle)
        .map_err(|error| record_error(format!("parse lifecycle state: {error}")))?;
    if !["tuned", "inconclusive"].contains(&lifecycle_state.phase.as_str()) {
        return Err(record_error(
            "only a completed optimization can receive an optimizer seal",
        ));
    }
    let seal = OptimizerSeal {
        schema_version: SEAL_SCHEMA,
        contract_sha256,
        run_record_sha256: contract::hash_bytes(&run_record),
        optimizer_sha256: contract::hash_bytes(&optimizer),
    };
    let bytes = contract::json_bytes(&seal, "serialize optimizer seal")?;
    contract::atomic_private_write(&run_dir.join("optimizer.seal.json"), &bytes, 0o400)
}

pub fn validate_run(run_dir: &Path) -> Result<ValidatedRun> {
    let lifecycle_bytes =
        contract::read_private_file(&run_dir.join("lifecycle.json"), "lifecycle state")?;
    let lifecycle: Lifecycle = serde_json::from_slice(&lifecycle_bytes)
        .map_err(|error| record_error(format!("parse lifecycle state: {error}")))?;
    if lifecycle.schema_version != STATE_SCHEMA {
        return Err(record_error("unsupported lifecycle state schema"));
    }
    let record_bytes = contract::read_private_file(&run_dir.join("run.json"), "run record")?;
    let record: serde_json::Value = serde_json::from_slice(&record_bytes)
        .map_err(|error| record_error(format!("parse run record: {error}")))?;
    let seal_bytes = contract::read_private_file(&run_dir.join("run.seal.json"), "run seal")?;
    let seal: RunSeal = serde_json::from_slice(&seal_bytes)
        .map_err(|error| record_error(format!("parse run seal: {error}")))?;
    if seal.schema_version != SEAL_SCHEMA
        || seal.run_record_sha256 != contract::hash_bytes(&record_bytes)
        || seal.baseline_manifest_sha256
            != crate::workspace::manifest_hash(&crate::workspace::manifest_tree(
                &run_dir.join("baseline"),
            )?)?
        || seal.stage_manifest_sha256
            != crate::workspace::manifest_hash(&crate::workspace::manifest_tree(
                &run_dir.join("stage"),
            )?)?
        || seal.patch_sha256
            != contract::hash_private_file(&run_dir.join("changes.patch"), "review patch")?
        || seal.readonly_canary_sha256
            != contract::hash_private_file(&run_dir.join("readonly-canary"), "readonly canary")?
    {
        return Err(record_error(
            "run evidence seal mismatch; persisted results are invalid",
        ));
    }
    let record_contract = record
        .get("contract_sha256")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if seal.contract_sha256 != record_contract {
        return Err(record_error("run contract seal mismatch"));
    }
    if let Some(expected) = record_contract.as_deref() {
        let (_, actual) = contract::load(run_dir)?;
        if expected != actual {
            return Err(record_error(
                "run contract was altered; persisted results are invalid",
            ));
        }
    }
    let optimizer_path = run_dir.join("optimizer.json");
    let optimizer_seal_path = run_dir.join("optimizer.seal.json");
    let optimizer_exists = optimizer_path.exists();
    let optimizer_seal_exists = optimizer_seal_path.exists();
    if optimizer_exists != optimizer_seal_exists {
        return Err(record_error(
            "optimizer result is incomplete or missing its integrity seal",
        ));
    }
    let optimizer = if optimizer_exists {
        let (_, contract_sha256) = contract::load(run_dir)?;
        let optimizer_bytes = contract::read_private_file(&optimizer_path, "optimizer result")?;
        let optimizer: serde_json::Value = serde_json::from_slice(&optimizer_bytes)
            .map_err(|error| record_error(format!("parse optimizer result: {error}")))?;
        let seal_bytes = contract::read_private_file(&optimizer_seal_path, "optimizer seal")?;
        let optimizer_seal: OptimizerSeal = serde_json::from_slice(&seal_bytes)
            .map_err(|error| record_error(format!("parse optimizer seal: {error}")))?;
        if optimizer_seal.schema_version != SEAL_SCHEMA
            || optimizer_seal.contract_sha256 != contract_sha256
            || optimizer_seal.run_record_sha256 != seal.run_record_sha256
            || optimizer_seal.optimizer_sha256 != contract::hash_bytes(&optimizer_bytes)
            || !["tuned", "inconclusive"].contains(&lifecycle.phase.as_str())
        {
            return Err(record_error(
                "optimizer evidence seal mismatch; persisted result is invalid",
            ));
        }
        Some(optimizer)
    } else {
        None
    };
    Ok(ValidatedRun {
        record,
        optimizer,
        lifecycle,
        record_sha256: seal.run_record_sha256,
        contract_sha256: record_contract,
    })
}

pub fn read_lifecycle(run_dir: &Path) -> Result<Lifecycle> {
    let bytes = contract::read_private_file(&run_dir.join("lifecycle.json"), "lifecycle state")?;
    let state: Lifecycle = serde_json::from_slice(&bytes)
        .map_err(|error| record_error(format!("parse lifecycle state: {error}")))?;
    if state.schema_version != STATE_SCHEMA {
        return Err(record_error("unsupported lifecycle state schema"));
    }
    Ok(state)
}

pub fn remove_known_temporary_files(run_dir: &Path) -> Result<usize> {
    let mut control_dirs = vec![run_dir.to_path_buf()];
    for relative in ["tuning", "tuning/replays", "tuning/source-check"] {
        let path = run_dir.join(relative);
        if is_private_directory(&path)? {
            control_dirs.push(path);
        }
    }
    let replay_parent = run_dir.join("tuning/replays");
    if is_private_directory(&replay_parent)? {
        for entry in fs::read_dir(&replay_parent)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "list replay directory", error))?
        {
            let entry = entry.map_err(|error| {
                AutoCageError::io(ErrorKind::Record, "read replay directory entry", error)
            })?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("trial-") && is_private_directory(&entry.path())?
            {
                control_dirs.push(entry.path());
            }
        }
    }
    let mut removed = 0;
    for dir in control_dirs {
        for entry in fs::read_dir(&dir).map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "list run control directory", error)
        })? {
            let entry = entry.map_err(|error| {
                AutoCageError::io(ErrorKind::Record, "read run control entry", error)
            })?;
            let leaf = entry.file_name();
            let name = leaf.to_string_lossy();
            let known_temp = [
                ".run.json.tmp-",
                ".contract.json.tmp-",
                ".optimizer.json.tmp-",
                ".lifecycle.json.tmp-",
                ".run.seal.json.tmp-",
                ".optimizer.seal.json.tmp-",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix));
            if known_temp {
                let meta = fs::symlink_metadata(entry.path()).map_err(|error| {
                    AutoCageError::io(ErrorKind::Record, "inspect temporary record", error)
                })?;
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(record_error(
                        "refusing to remove non-regular temporary evidence",
                    ));
                }
                fs::remove_file(entry.path()).map_err(|error| {
                    AutoCageError::io(
                        ErrorKind::Record,
                        "remove incomplete temporary evidence",
                        error,
                    )
                })?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

fn is_private_directory(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(AutoCageError::io(
                ErrorKind::Record,
                "inspect recovery directory",
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(false);
    }
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(record_error(
            "recovery control directory must be private and owned by the current user",
        ));
    }
    Ok(true)
}

pub fn mark_interrupted(run_dir: &Path) -> Result<usize> {
    let state = read_lifecycle(run_dir)?;
    if ["complete", "tuned", "inconclusive", "interrupted"].contains(&state.phase.as_str())
        && validate_run(run_dir).is_ok()
    {
        return Err(record_error(format!(
            "run is already complete and sealed: {}",
            state.phase
        )));
    }
    let removed = remove_known_temporary_files(run_dir)?;
    write_lifecycle(run_dir, "interrupted", state.current_trial)?;
    Ok(removed)
}

fn record_error(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Record, message)
}
