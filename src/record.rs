use crate::cli::CommandSpec;
use crate::error::Result;
use crate::policy::ExecutionPolicy;
use crate::preflight::HostFacts;
use crate::workspace::{WorkspaceOutcome, WorkspaceSnapshot};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub exit_code: i32,
    pub timed_out: bool,
    pub elapsed_millis: u128,
}

#[derive(Debug, Serialize)]
pub struct CommandRecord {
    pub executable_name: String,
    pub argv_sha256: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub elapsed_millis: u128,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCheckStatus {
    Passed,
    Failed,
    NotTested,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SecurityCheckRecord {
    pub name: String,
    pub status: SecurityCheckStatus,
    pub required_for_policy_promotion: bool,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceRecord {
    pub before_manifest_sha256: String,
    pub after_manifest_sha256: String,
    pub omissions: Vec<String>,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RunPhaseTimings {
    /// Time spent in platform/kernel/Bubblewrap preflight, before staging.
    pub preflight_elapsed_millis: u128,
    /// Private copy and source manifest construction.
    pub workspace_stage_elapsed_millis: u128,
    /// Policy validation and verifier-root snapshot preparation.
    pub policy_validation_elapsed_millis: u128,
    /// Deterministic construction of the Bubblewrap argv for each child.
    /// This excludes Bubblewrap startup and mount operations.
    pub agent_backend_compile_elapsed_millis: u128,
    pub verifier_backend_compile_elapsed_millis: Option<u128>,
    pub readonly_canary_backend_compile_elapsed_millis: u128,
    /// End-to-end supervisor elapsed time up to creation of the run record;
    /// includes process launch, commands, workspace finalization and hashing.
    pub supervisor_elapsed_before_record_millis: u128,
}

#[derive(Debug, Serialize)]
pub struct RunRecord {
    pub schema_version: u32,
    pub run_id: String,
    pub started_unix_millis: u128,
    pub completed_unix_millis: u128,
    pub runtime: HostFacts,
    pub phase_timings: RunPhaseTimings,
    pub policy: ExecutionPolicy,
    pub authorized_ceiling: ExecutionPolicy,
    pub accepted_proposal_sha256: Option<String>,
    pub contract_sha256: Option<String>,
    pub agent: CommandRecord,
    pub verifier: Option<CommandRecord>,
    pub readonly_mount_canary: CommandRecord,
    pub security_checks: Vec<SecurityCheckRecord>,
    pub verifier_readonly_paths: Vec<String>,
    pub workspace: WorkspaceRecord,
    pub outcome: String,
    pub patch_file: &'static str,
}

pub struct RunRecordInput<'a> {
    pub run_id: String,
    pub started_unix_millis: u128,
    pub runtime: HostFacts,
    pub phase_timings: RunPhaseTimings,
    pub agent: CommandRecord,
    pub verifier: Option<CommandRecord>,
    pub readonly_mount_canary: CommandRecord,
    pub security_checks: Vec<SecurityCheckRecord>,
    pub verifier_readonly_paths: Vec<String>,
    pub policy: ExecutionPolicy,
    pub authorized_ceiling: ExecutionPolicy,
    pub accepted_proposal_sha256: Option<String>,
    pub contract_sha256: Option<String>,
    pub snapshot: &'a WorkspaceSnapshot,
    pub workspace: &'a WorkspaceOutcome,
    pub outcome: String,
}

impl CommandRecord {
    pub fn new(spec: &CommandSpec, outcome: &ProcessOutcome) -> Self {
        let executable_name = Path::new(&spec.program)
            .file_name()
            .unwrap_or_else(|| OsStr::new("unknown"))
            .to_string_lossy()
            .into_owned();
        Self {
            executable_name,
            argv_sha256: argv_hash(spec),
            exit_code: outcome.exit_code,
            timed_out: outcome.timed_out,
            elapsed_millis: outcome.elapsed_millis,
        }
    }
}

impl RunRecord {
    pub fn new(input: RunRecordInput<'_>) -> Self {
        Self {
            schema_version: 4,
            run_id: input.run_id,
            started_unix_millis: input.started_unix_millis,
            completed_unix_millis: now_millis(),
            runtime: input.runtime,
            phase_timings: input.phase_timings,
            policy: input.policy,
            authorized_ceiling: input.authorized_ceiling,
            accepted_proposal_sha256: input.accepted_proposal_sha256,
            contract_sha256: input.contract_sha256,
            agent: input.agent,
            verifier: input.verifier,
            readonly_mount_canary: input.readonly_mount_canary,
            security_checks: input.security_checks,
            verifier_readonly_paths: input.verifier_readonly_paths,
            workspace: WorkspaceRecord {
                before_manifest_sha256: input.snapshot.before_hash.clone(),
                after_manifest_sha256: input.workspace.after_hash.clone(),
                omissions: input.snapshot.omissions.clone(),
                changed_paths: input.workspace.changed_paths.clone(),
            },
            outcome: input.outcome,
            patch_file: "changes.patch",
        }
    }

    pub fn write(&self, run_dir: &Path) -> Result<PathBuf> {
        let final_path = run_dir.join("run.json");
        let bytes = crate::contract::json_bytes(self, "serialize run record")?;
        crate::contract::atomic_private_write(&final_path, &bytes, 0o400)?;
        Ok(final_path)
    }
}

pub fn argv_hash(spec: &CommandSpec) -> String {
    let mut digest = Sha256::new();
    hash_os_str(&mut digest, &spec.program);
    for arg in &spec.args {
        hash_os_str(&mut digest, arg);
    }
    crate::digest::hex(&digest.finalize())
}

fn hash_os_str(digest: &mut Sha256, value: &OsStr) {
    let bytes = value.as_bytes();
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
