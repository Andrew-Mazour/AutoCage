//! Versioned, privacy-preserving replay contracts.
//!
//! Contracts bind a replay to executable and argv digests without persisting
//! argument values. `tune` requires the caller to re-supply the exact commands.

use crate::cli::CommandSpec;
use crate::error::{AutoCageError, ErrorKind, Result};
use crate::policy::ExecutionPolicy;
use crate::preflight::HostFacts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const CONTRACT_SCHEMA: u32 = 2;
const BACKEND_PROFILE: &str = "bubblewrap-policy-v2:user,mount,pid,ipc,uts,net;disable-userns;ro-usr;ro-stage+grant-overlays;private-tmp;clearenv;close-range-cloexec";
const ENVIRONMENT_PROFILE: &str = "PATH=/usr/bin:/bin;HOME=/tmp/home;TMPDIR=/tmp;PWD=/workspace;LANG=C.UTF-8;PYTHONDONTWRITEBYTECODE=1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandIdentity {
    pub executable_name: String,
    pub executable_sha256: String,
    pub argv_sha256: String,
    pub argument_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifierRootIdentity {
    pub relative_path: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub autocage_sha256: String,
    pub bubblewrap_sha256: String,
    pub package_inventory_sha256: String,
    pub backend_profile_sha256: String,
    pub environment_profile_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunContract {
    pub schema_version: u32,
    pub workspace_path_sha256: String,
    pub source_manifest_sha256: String,
    pub agent: CommandIdentity,
    pub verifier: CommandIdentity,
    pub verifier_roots: Vec<VerifierRootIdentity>,
    pub timeout_seconds: u64,
    pub authorized_ceiling: ExecutionPolicy,
    pub host: HostFacts,
    pub runtime: RuntimeIdentity,
}

pub struct RunContractInput<'a> {
    pub workspace: PathBuf,
    pub source_manifest_sha256: String,
    pub agent: &'a CommandSpec,
    pub verifier: &'a CommandSpec,
    pub verifier_roots: Vec<VerifierRootIdentity>,
    pub timeout: Duration,
    pub authorized_ceiling: ExecutionPolicy,
    pub host: HostFacts,
}

impl RunContract {
    pub fn new(input: RunContractInput<'_>) -> Result<Self> {
        let workspace = input.workspace.canonicalize().map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "resolve contract workspace", error)
        })?;
        if input.timeout.is_zero() || input.timeout.as_secs() == 0 {
            return Err(record_error("replay timeout must be at least one second"));
        }
        let agent = command_identity(input.agent)?;
        let verifier = command_identity(input.verifier)?;
        validate_verifier_inputs(&workspace, input.verifier, &input.verifier_roots)?;
        let runtime = runtime_identity(&input.host)?;
        let authorized_ceiling = input.authorized_ceiling.normalize()?;
        Ok(Self {
            schema_version: CONTRACT_SCHEMA,
            workspace_path_sha256: hash_bytes(workspace.as_os_str().as_bytes()),
            source_manifest_sha256: input.source_manifest_sha256,
            agent,
            verifier,
            verifier_roots: input.verifier_roots,
            timeout_seconds: input.timeout.as_secs(),
            authorized_ceiling,
            host: input.host,
            runtime,
        })
    }

    pub fn validate_commands(&self, agent: &CommandSpec, verifier: &CommandSpec) -> Result<()> {
        if command_identity(agent)? != self.agent {
            return Err(record_error(
                "agent executable or arguments differ from the replay contract",
            ));
        }
        if command_identity(verifier)? != self.verifier {
            return Err(record_error(
                "verifier executable or arguments differ from the replay contract",
            ));
        }
        Ok(())
    }
}

fn validate_verifier_inputs(
    workspace: &Path,
    verifier: &CommandSpec,
    roots: &[VerifierRootIdentity],
) -> Result<()> {
    let normalized_roots = normalized_verifier_roots(roots)?;

    for argument in &verifier.args {
        let Some(text) = argument.to_str() else {
            continue;
        };
        let raw = Path::new(text);
        let Some(relative) = workspace_relative_argument(raw)? else {
            continue;
        };
        let candidate = workspace.join(&relative);
        if !candidate.exists() {
            continue;
        }
        if !normalized_roots
            .iter()
            .any(|root| relative == *root || relative.starts_with(root))
        {
            return Err(record_error(format!(
                "verifier workspace input {} is outside every --verify-readonly root",
                relative.display()
            )));
        }
        let canonical = candidate.canonicalize().map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "resolve verifier workspace input", error)
        })?;
        let relative = canonical.strip_prefix(workspace).map_err(|_| {
            record_error("verifier workspace input resolves outside the staged workspace")
        })?;
        if !normalized_roots
            .iter()
            .any(|root| relative == root || relative.starts_with(root))
        {
            return Err(record_error(format!(
                "verifier input target {} is outside every --verify-readonly root",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn workspace_relative_argument(path: &Path) -> Result<Option<PathBuf>> {
    let mut components = if path.is_absolute() {
        Vec::new()
    } else {
        vec!["workspace".to_owned()]
    };
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                components.pop();
            }
            Component::Prefix(_) => {
                return Err(record_error(
                    "verifier file arguments use an unsupported path prefix",
                ));
            }
        }
    }
    if components.first().is_some_and(|part| part == "workspace") {
        Ok(Some(components.into_iter().skip(1).collect()))
    } else {
        Ok(None)
    }
}

fn normalized_verifier_roots(roots: &[VerifierRootIdentity]) -> Result<Vec<PathBuf>> {
    if roots.is_empty() {
        return Err(record_error(
            "replay contracts require declared read-only verifier input roots",
        ));
    }
    let mut normalized = Vec::with_capacity(roots.len());
    for root in roots {
        validate_sha(&root.manifest_sha256, "verifier input")?;
        let path = Path::new(&root.relative_path);
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(record_error(
                "verifier input root is not a normalized relative path",
            ));
        }
        if normalized.iter().any(|existing: &PathBuf| {
            path == existing || path.starts_with(existing) || existing.starts_with(path)
        }) {
            return Err(record_error(
                "verifier input roots must be distinct and non-overlapping",
            ));
        }
        normalized.push(path.to_path_buf());
    }
    Ok(normalized)
}

pub fn workspace_path_hash(path: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "resolve replay workspace", error))?;
    Ok(hash_bytes(canonical.as_os_str().as_bytes()))
}

pub fn runtime_identity(host: &HostFacts) -> Result<RuntimeIdentity> {
    let autocage = std::env::current_exe()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "resolve AutoCage runtime", error))?;
    Ok(RuntimeIdentity {
        autocage_sha256: hash_file(&autocage)?,
        bubblewrap_sha256: hash_file(&host.bubblewrap_path)?,
        package_inventory_sha256: hash_file(Path::new("/var/lib/dpkg/status"))?,
        backend_profile_sha256: hash_bytes(BACKEND_PROFILE.as_bytes()),
        environment_profile_sha256: hash_bytes(ENVIRONMENT_PROFILE.as_bytes()),
    })
}

pub fn command_identity(spec: &CommandSpec) -> Result<CommandIdentity> {
    let executable_name = Path::new(&spec.program)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| record_error("command executable must have a UTF-8 basename"))?
        .to_owned();
    let argv_sha256 = crate::record::argv_hash(spec);
    Ok(CommandIdentity {
        executable_name,
        executable_sha256: executable_hash(&spec.program)?,
        argv_sha256,
        argument_count: spec.args.len(),
    })
}

pub fn write(contract: &RunContract, run_dir: &Path) -> Result<String> {
    let bytes = json_bytes(contract, "serialize replay contract")?;
    let path = run_dir.join("contract.json");
    atomic_private_write(&path, &bytes, 0o400)?;
    Ok(hash_bytes(&bytes))
}

pub fn load(run_dir: &Path) -> Result<(RunContract, String)> {
    let path = run_dir.join("contract.json");
    let bytes = read_private_file(&path, "replay contract")?;
    let contract: RunContract = serde_json::from_slice(&bytes).map_err(|error| {
        AutoCageError::new(ErrorKind::Record, format!("parse replay contract: {error}"))
    })?;
    if contract.schema_version != CONTRACT_SCHEMA {
        return Err(record_error(
            "unsupported replay contract schema; create a new run",
        ));
    }
    validate_sha(&contract.workspace_path_sha256, "workspace path")?;
    validate_sha(&contract.source_manifest_sha256, "source snapshot")?;
    validate_sha(&contract.agent.executable_sha256, "agent executable")?;
    validate_sha(&contract.agent.argv_sha256, "agent argv")?;
    validate_sha(&contract.verifier.executable_sha256, "verifier executable")?;
    validate_sha(&contract.verifier.argv_sha256, "verifier argv")?;
    validate_sha(&contract.runtime.autocage_sha256, "AutoCage runtime")?;
    validate_sha(&contract.runtime.bubblewrap_sha256, "Bubblewrap runtime")?;
    validate_sha(
        &contract.runtime.package_inventory_sha256,
        "runtime package inventory",
    )?;
    validate_sha(&contract.runtime.backend_profile_sha256, "backend profile")?;
    validate_sha(
        &contract.runtime.environment_profile_sha256,
        "environment profile",
    )?;
    if contract.timeout_seconds == 0 {
        return Err(record_error("replay contract has an invalid timeout"));
    }
    contract.authorized_ceiling.validate_global_invariants()?;
    normalized_verifier_roots(&contract.verifier_roots)?;
    if contract.authorized_ceiling.normalize()? != contract.authorized_ceiling {
        return Err(record_error("replay ceiling is not canonically normalized"));
    }
    Ok((contract, hash_bytes(&bytes)))
}

pub fn executable_hash(program: &OsStr) -> Result<String> {
    let path = Path::new(program);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let path_value = std::env::var_os("PATH").unwrap_or_default();
        std::env::split_paths(&path_value)
            .map(|directory| directory.join(path))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| record_error(format!("cannot resolve executable {}", path.display())))?
    };
    hash_file(&resolved)
}

pub fn atomic_private_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write_impl(path, bytes, mode, false)
}

pub fn atomic_replace_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write_impl(path, bytes, mode, true)
}

fn atomic_write_impl(path: &Path, bytes: &[u8], mode: u32, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| record_error("record path has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| record_error("record path has no filename"))?
        .to_string_lossy();
    let temp = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "create private temporary record", error)
        })?;
    file.write_all(bytes)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "write private record", error))?;
    file.sync_all()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "sync private record", error))?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode)).map_err(|error| {
        AutoCageError::io(ErrorKind::Record, "set private record permissions", error)
    })?;
    drop(file);
    if replace {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(record_error(
                    "refusing to replace non-regular evidence path",
                ));
            }
        }
        fs::rename(&temp, path).map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "replace private record", error)
        })?;
    } else {
        // hard_link is an atomic no-replace commit on the same filesystem.
        fs::hard_link(&temp, path).map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "commit private record", error)
        })?;
        fs::remove_file(&temp).map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "remove temporary record", error)
        })?;
    }
    sync_directory(parent)?;
    Ok(())
}

pub fn read_private_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, format!("inspect {label}"), error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(record_error(format!(
            "{label} must be a private regular file"
        )));
    }
    fs::read(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, format!("read {label}"), error))
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    crate::digest::hex(&Sha256::digest(bytes))
}

pub fn json_bytes<T: Serialize>(value: &T, context: &str) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| AutoCageError::new(ErrorKind::Record, format!("{context}: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn sync_directory(path: &Path) -> Result<()> {
    let dir = File::open(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "open record directory", error))?;
    dir.sync_all()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "sync record directory", error))
}

fn validate_sha(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(record_error(format!(
            "invalid {label} SHA-256 in replay contract"
        )));
    }
    Ok(())
}

pub fn hash_file(path: &Path) -> Result<String> {
    let canonical = path
        .canonicalize()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "resolve file identity", error))?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| {
        AutoCageError::io(ErrorKind::Record, "inspect executable identity", error)
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(record_error("command executable is not a regular file"));
    }
    let bytes = fs::read(canonical)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "read executable identity", error))?;
    Ok(hash_bytes(&bytes))
}

pub fn hash_private_file(path: &Path, label: &str) -> Result<String> {
    Ok(hash_bytes(&read_private_file(path, label)?))
}

fn record_error(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Record, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn contract_does_not_persist_argument_values_and_round_trips() {
        let dir = temp_dir();
        let agent = CommandSpec {
            program: "/usr/bin/true".into(),
            args: vec!["task-secret-value".into()],
        };
        let verifier = CommandSpec {
            program: "/usr/bin/true".into(),
            args: vec!["-q".into()],
        };
        let contract = RunContract::new(RunContractInput {
            workspace: dir.clone(),
            source_manifest_sha256: hash_bytes(b"snapshot"),
            agent: &agent,
            verifier: &verifier,
            verifier_roots: vec![VerifierRootIdentity {
                relative_path: "contract-inputs".to_owned(),
                manifest_sha256: hash_bytes(b"contract inputs"),
            }],
            timeout: Duration::from_secs(2),
            authorized_ceiling: ExecutionPolicy::baseline(),
            host: minimal_facts(),
        })
        .unwrap();
        let hash = write(&contract, &dir).unwrap();
        let (loaded, actual_hash) = load(&dir).unwrap();
        let bytes = fs::read(dir.join("contract.json")).unwrap();
        assert_eq!(loaded.agent.argument_count, 1);
        assert!(!String::from_utf8_lossy(&bytes).contains("task-secret-value"));
        assert_eq!(hash, actual_hash);
        assert_eq!(
            fs::metadata(dir.join("contract.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        loaded.validate_commands(&agent, &verifier).unwrap();
        let changed = CommandSpec {
            program: "/usr/bin/true".into(),
            args: vec!["different".into()],
        };
        assert!(loaded.validate_commands(&changed, &verifier).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_atomic_write_refuses_overwrite_and_symlinks() {
        let dir = temp_dir();
        let path = dir.join("evidence.json");
        atomic_private_write(&path, b"one", 0o400).unwrap();
        assert!(atomic_private_write(&path, b"two", 0o400).is_err());
        let target = dir.join("target");
        fs::write(&target, "safe").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_private_file(&link, "test record").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "safe");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verifier_file_arguments_must_be_covered_by_a_readonly_root() {
        let dir = temp_dir();
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("tests/verify.py"), "assert True\n").unwrap();
        let verifier = CommandSpec {
            program: "/usr/bin/python3".into(),
            args: vec!["tests/verify.py".into()],
        };
        let tests_root = VerifierRootIdentity {
            relative_path: "tests".to_owned(),
            manifest_sha256: hash_bytes(b"tests"),
        };
        assert!(validate_verifier_inputs(&dir, &verifier, &[tests_root]).is_ok());

        let other_root = VerifierRootIdentity {
            relative_path: "src".to_owned(),
            manifest_sha256: hash_bytes(b"src"),
        };
        assert!(validate_verifier_inputs(&dir, &verifier, &[other_root]).is_err());
        assert!(validate_verifier_inputs(&dir, &verifier, &[]).is_err());

        let traversing_verifier = CommandSpec {
            program: "/usr/bin/python3".into(),
            args: vec!["../workspace/tests/verify.py".into()],
        };
        let untrusted_root = VerifierRootIdentity {
            relative_path: "src".to_owned(),
            manifest_sha256: hash_bytes(b"src"),
        };
        assert!(validate_verifier_inputs(&dir, &traversing_verifier, &[untrusted_root]).is_err());

        let directory_verifier = CommandSpec {
            program: "/usr/bin/pytest".into(),
            args: vec!["tests".into()],
        };
        let uncovered_directory = VerifierRootIdentity {
            relative_path: "src".to_owned(),
            manifest_sha256: hash_bytes(b"src"),
        };
        assert!(
            validate_verifier_inputs(&dir, &directory_verifier, &[uncovered_directory]).is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn temp_dir() -> PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "autocage-contract-{}-{}-{sequence}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn minimal_facts() -> HostFacts {
        HostFacts {
            distribution: "ubuntu".into(),
            ubuntu_version: "24.04".into(),
            architecture: "aarch64".into(),
            kernel: "6.8".into(),
            euid: 1000,
            egid: 1000,
            // Contract unit tests use the test binary as a synthetic runtime
            // file so portable CI does not need Bubblewrap installed.
            bubblewrap_path: std::env::current_exe().unwrap(),
            bubblewrap_version: "0.9".into(),
            apparmor_enabled: "Y".into(),
            apparmor_userns_restricted: "1".into(),
            child_profile: "bwrap//&unpriv_bwrap (enforce)".into(),
            child_capabilities: Default::default(),
            child_uid_map: "x".into(),
            child_gid_map: "x".into(),
        }
    }
}
