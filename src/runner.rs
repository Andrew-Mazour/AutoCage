use crate::backend::bubblewrap::{BubblewrapBackend, ReadOnlyMount};
use crate::cli::{CommandSpec, RunOptions};
use crate::contract::{self, RunContract, RunContractInput};
use crate::error::{AutoCageError, ErrorKind, Result};
use crate::journal;
use crate::optimizer::{self, OptimizationResult, SearchStrategy, TrialObservation};
use crate::policy::ExecutionPolicy;
use crate::preflight;
use crate::profile::{self, PolicyProposal};
use crate::record::{
    self, CommandRecord, ProcessOutcome, RunRecord, RunRecordInput, SecurityCheckRecord,
    SecurityCheckStatus,
};
use crate::workspace;
use std::ffi::{CString, OsStr};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RunSummary {
    pub run_dir: PathBuf,
    pub record_path: PathBuf,
    pub patch_path: PathBuf,
    pub exit_code: i32,
    pub verified: bool,
    pub before_manifest: Vec<workspace::ManifestEntry>,
    pub after_manifest: Vec<workspace::ManifestEntry>,
}

pub fn run(options: RunOptions) -> Result<RunSummary> {
    if options.record_contract && options.verifier_readonly.is_empty() {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "--record-contract requires at least one --verify-readonly root; replayable policies require declared immutable verifier inputs",
        ));
    }
    let record_contract = options.record_contract;
    let accepted_proposal = options
        .accepted_proposal
        .as_deref()
        .map(profile::read)
        .transpose()?;
    let authorized_ceiling = options.authorized_ceiling.clone();
    let (policy, ceiling) = match accepted_proposal.as_ref() {
        Some((proposal, _)) => {
            let ceiling = authorized_ceiling.as_ref().ok_or_else(|| {
                AutoCageError::new(
                    ErrorKind::Policy,
                    "accepted proposal has no explicit developer-authorized ceiling",
                )
            })?;
            if !proposal.policy.is_subset_of(ceiling)? {
                return Err(AutoCageError::new(
                    ErrorKind::Policy,
                    "suggested policy exceeds the separately authorized developer ceiling",
                ));
            }
            (proposal.policy.clone(), Some(ceiling))
        }
        None => (options.policy.clone(), None),
    };
    run_with_policy(options, policy, record_contract, ceiling, accepted_proposal)
}

fn run_with_policy(
    options: RunOptions,
    policy: ExecutionPolicy,
    save_contract: bool,
    authorized_ceiling: Option<&ExecutionPolicy>,
    accepted_proposal: Option<(PolicyProposal, String)>,
) -> Result<RunSummary> {
    let supervisor_started = Instant::now();
    let phase_started = Instant::now();
    let runtime = preflight::check()?;
    let preflight_elapsed_millis = phase_started.elapsed().as_millis();
    let workspace_root = options
        .workspace
        .canonicalize()
        .map_err(|error| AutoCageError::io(ErrorKind::Stage, "resolve source workspace", error))?;
    if !workspace_root.is_dir() {
        return Err(AutoCageError::new(
            ErrorKind::Stage,
            "workspace must be a directory",
        ));
    }
    let (run_id, run_dir) = create_run_directory(options.run_dir.as_deref(), &workspace_root)?;
    let _run_lock = journal::lock(&run_dir)?;
    journal::write_lifecycle(&run_dir, "preparing", None)?;
    if let Some(ceiling) = authorized_ceiling {
        if !policy.is_subset_of(ceiling)? {
            return Err(AutoCageError::new(
                ErrorKind::Policy,
                "replay candidate exceeds the recorded authorized ceiling",
            ));
        }
    }
    let started_unix_millis = record::now_millis();
    let phase_started = Instant::now();
    let snapshot = workspace::prepare(&workspace_root, &run_dir)?;
    let workspace_stage_elapsed_millis = phase_started.elapsed().as_millis();
    if let Some((proposal, _)) = &accepted_proposal {
        let ceiling = authorized_ceiling.ok_or_else(|| {
            AutoCageError::new(
                ErrorKind::Policy,
                "accepted proposal has no explicit developer-authorized ceiling",
            )
        })?;
        profile::validate_for_snapshot(proposal, &snapshot.baseline, &options.command, ceiling)?;
    }
    let phase_started = Instant::now();
    policy.validate(&snapshot.stage)?;
    let protected = workspace::protected_verifier_roots(&snapshot, &options.verifier_readonly)?;
    let policy_validation_elapsed_millis = phase_started.elapsed().as_millis();

    let contract_hash = if save_contract {
        let verifier = options.verifier.as_ref().ok_or_else(|| {
            AutoCageError::new(ErrorKind::Record, "--record-contract requires a verifier")
        })?;
        let contract = RunContract::new(RunContractInput {
            workspace: workspace_root.clone(),
            source_manifest_sha256: snapshot.before_hash.clone(),
            agent: &options.command,
            verifier,
            verifier_roots: verifier_root_identities(&snapshot, &protected)?,
            timeout: options.timeout,
            authorized_ceiling: authorized_ceiling
                .cloned()
                .unwrap_or_else(|| policy.clone()),
            host: runtime.clone(),
        })?;
        Some(contract::write(&contract, &run_dir)?)
    } else {
        None
    };

    let source_before = workspace::manifest_hash(&workspace::manifest_tree(&workspace_root)?)?;

    let backend = BubblewrapBackend {
        binary: runtime.bubblewrap_path.clone(),
    };
    journal::write_lifecycle(&run_dir, "agent_running", None)?;
    let phase_started = Instant::now();
    let agent_command = backend.command(&policy, Some(&snapshot.stage), &[], &options.command)?;
    let agent_backend_compile_elapsed_millis = phase_started.elapsed().as_millis();
    let agent_outcome = run_bounded(agent_command, options.timeout)?;

    let mut verifier_result: Option<(CommandSpec, ProcessOutcome)> = None;
    let mut verifier_backend_compile_elapsed_millis = None;
    if agent_outcome.exit_code == 0 && !agent_outcome.timed_out {
        if let Some(verifier) = options.verifier.clone() {
            let mounts = protected
                .iter()
                .map(|root| ReadOnlyMount {
                    source: root.source.clone(),
                    destination: root.destination.clone(),
                })
                .collect::<Vec<_>>();
            let phase_started = Instant::now();
            let verifier_command =
                backend.command(&policy, Some(&snapshot.stage), &mounts, &verifier)?;
            verifier_backend_compile_elapsed_millis = Some(phase_started.elapsed().as_millis());
            journal::write_lifecycle(&run_dir, "verifier_running", None)?;
            let outcome = run_bounded(verifier_command, options.timeout)?;
            verifier_result = Some((verifier, outcome));
        }
    }

    let (readonly_canary_path, readonly_canary_spec) = create_readonly_canary(&run_dir)?;
    let phase_started = Instant::now();
    let readonly_canary_command = backend.command(
        &policy,
        Some(&snapshot.stage),
        &[ReadOnlyMount {
            source: readonly_canary_path.clone(),
            destination: "/autocage-readonly-canary".to_owned(),
        }],
        &readonly_canary_spec,
    )?;
    let readonly_canary_backend_compile_elapsed_millis = phase_started.elapsed().as_millis();
    let readonly_canary_outcome = run_bounded(readonly_canary_command, Duration::from_secs(5))?;
    let canary_file_unchanged = fs::read_to_string(&readonly_canary_path)
        .map(|value| value == "AUTOCAGE-READONLY-CANARY-v1\n")
        .unwrap_or(false);
    let readonly_canary_passed = readonly_canary_outcome.exit_code == 0
        && !readonly_canary_outcome.timed_out
        && canary_file_unchanged;

    let (workspace_outcome, patch_path) = workspace::finish(&snapshot, &run_dir)?;
    let source_after = workspace::manifest_hash(&workspace::manifest_tree(&workspace_root)?)?;
    if source_before != source_after {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "source workspace changed during sandboxed execution",
        ));
    }
    let agent_record = CommandRecord::new(&options.command, &agent_outcome);
    let verifier_record = verifier_result
        .as_ref()
        .map(|(spec, outcome)| CommandRecord::new(spec, outcome));
    let outcome_name = if readonly_canary_passed {
        classify_outcome(&agent_outcome, verifier_result.as_ref())
    } else {
        "security_canary_failed".to_owned()
    };
    let exit_code = if readonly_canary_passed {
        outcome_exit_code(&agent_outcome, verifier_result.as_ref())
    } else {
        94
    };
    let verifier_paths = protected
        .iter()
        .map(|root| root.relative_path.clone())
        .collect();
    let phase_timings = record::RunPhaseTimings {
        preflight_elapsed_millis,
        workspace_stage_elapsed_millis,
        policy_validation_elapsed_millis,
        agent_backend_compile_elapsed_millis,
        verifier_backend_compile_elapsed_millis,
        readonly_canary_backend_compile_elapsed_millis,
        supervisor_elapsed_before_record_millis: supervisor_started.elapsed().as_millis(),
    };
    let is_verified = outcome_name == "verified";
    let run_record = RunRecord::new(RunRecordInput {
        run_id,
        started_unix_millis,
        runtime,
        phase_timings,
        agent: agent_record,
        verifier: verifier_record,
        readonly_mount_canary: CommandRecord::new(&readonly_canary_spec, &readonly_canary_outcome),
        security_checks: vec![
            SecurityCheckRecord {
                name: "required_namespace_preflight".to_owned(),
                status: SecurityCheckStatus::Passed,
                required_for_policy_promotion: true,
                evidence: "preflight succeeded before the task process was launched".to_owned(),
            },
            SecurityCheckRecord {
                name: "authorized_ceiling_subset".to_owned(),
                status: if authorized_ceiling.is_some() {
                    SecurityCheckStatus::Passed
                } else {
                    SecurityCheckStatus::NotTested
                },
                required_for_policy_promotion: authorized_ceiling.is_some(),
                evidence: if authorized_ceiling.is_some() {
                    "candidate policy was checked against the recorded ceiling".to_owned()
                } else {
                    "not applicable to an initial developer-authorized run".to_owned()
                },
            },
            SecurityCheckRecord {
                name: "accepted_pre_execution_profile_identity".to_owned(),
                status: if accepted_proposal.is_some() {
                    SecurityCheckStatus::Passed
                } else {
                    SecurityCheckStatus::NotTested
                },
                required_for_policy_promotion: accepted_proposal.is_some(),
                evidence: if let Some((_, digest)) = &accepted_proposal {
                    format!("proposal was recomputed against the staged source snapshot and command; sha256={digest}")
                } else {
                    "no pre-execution proposal was accepted".to_owned()
                },
            },
            SecurityCheckRecord {
                name: "source_checkout_unchanged".to_owned(),
                status: SecurityCheckStatus::Passed,
                required_for_policy_promotion: true,
                evidence: "before/after source manifest digests matched".to_owned(),
            },
            SecurityCheckRecord {
                name: "readonly_mount_write_denial".to_owned(),
                status: if readonly_canary_passed {
                    SecurityCheckStatus::Passed
                } else {
                    SecurityCheckStatus::Failed
                },
                required_for_policy_promotion: true,
                evidence: format!(
                    "probe exit {}; canary unchanged={canary_file_unchanged}",
                    readonly_canary_outcome.exit_code
                ),
            },
            SecurityCheckRecord {
                name: "external_host_canary".to_owned(),
                status: SecurityCheckStatus::NotTested,
                required_for_policy_promotion: false,
                evidence: "host-side canary is supplied by the independent integration/benchmark controller".to_owned(),
            },
        ],
        verifier_readonly_paths: verifier_paths,
        policy,
        authorized_ceiling: authorized_ceiling
            .cloned()
            .unwrap_or_else(|| options.policy.clone()),
        accepted_proposal_sha256: accepted_proposal.map(|(_, digest)| digest),
        contract_sha256: contract_hash.clone(),
        snapshot: &snapshot,
        workspace: &workspace_outcome,
        outcome: outcome_name,
    });
    let record_path = run_record.write(&run_dir)?;
    journal::write_lifecycle(&run_dir, "complete", None)?;
    journal::write_run_seal(&run_dir, contract_hash)?;
    Ok(RunSummary {
        run_dir,
        record_path,
        patch_path,
        exit_code,
        verified: is_verified && readonly_canary_passed,
        before_manifest: snapshot.before_manifest,
        after_manifest: workspace_outcome.after_manifest,
    })
}

pub fn tune(
    run_dir: &Path,
    workspace: &Path,
    agent: &CommandSpec,
    verifier: &CommandSpec,
    max_replays: usize,
    strategy: &str,
) -> Result<OptimizationResult> {
    let _run_lock = journal::lock(run_dir)?;
    let run_dir = run_dir
        .canonicalize()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "resolve run directory", error))?;
    let validated = journal::validate_run(&run_dir)?;
    if validated.lifecycle.phase != "complete" {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            format!(
                "tune requires a complete initial run; found {}",
                validated.lifecycle.phase
            ),
        ));
    }
    if validated.optimizer.is_some() {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "this run already has an optimization attempt; create a new run instead of reusing stale evidence",
        ));
    }
    let (contract, contract_hash) = contract::load(&run_dir)?;
    contract.validate_commands(agent, verifier)?;
    let record = validated.record;
    if record.get("outcome").and_then(serde_json::Value::as_str) != Some("verified") {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "tune requires an initially verified run",
        ));
    }
    if record
        .get("contract_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(contract_hash.as_str())
    {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "run contract hash does not match immutable run record",
        ));
    }
    if contract.verifier.executable_name.is_empty() || contract.schema_version != 2 {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "run contract is missing a valid verifier",
        ));
    }
    validate_contract_runtime(&contract)?;
    if contract::workspace_path_hash(workspace)? != contract.workspace_path_sha256 {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "workspace path identity changed since the initial run",
        ));
    }
    let initial_manifest = workspace::manifest_tree(&run_dir.join("baseline"))?;
    let initial_hash = workspace::manifest_hash(&initial_manifest)?;
    if initial_hash != contract.source_manifest_sha256 {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "saved source snapshot does not match replay contract",
        ));
    }
    let record_verifier_paths = record
        .get("verifier_readonly_paths")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            AutoCageError::new(ErrorKind::Record, "run record has no verifier-root list")
        })?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                AutoCageError::new(
                    ErrorKind::Record,
                    "invalid verifier-root entry in run record",
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let root_identities =
        verifier_root_identities_from_manifest(&initial_manifest, &record_verifier_paths)?;
    if root_identities != contract.verifier_roots {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "verifier inputs differ from the sealed source snapshot",
        ));
    }

    // Re-stage the current source once and compare its staged-content identity.
    // This catches source drift while preserving the original user checkout.
    let validation_dir = run_dir.join("tuning/source-check");
    create_private_run_directory(&run_dir.join("tuning"))
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "create tuning directory", error))?;
    create_private_run_directory(&validation_dir).map_err(|error| {
        AutoCageError::io(ErrorKind::Record, "create source-check directory", error)
    })?;
    let current = workspace::prepare(workspace, &validation_dir)?;
    let current_hash = current.before_hash.clone();
    fs::remove_dir_all(&validation_dir).map_err(|error| {
        AutoCageError::io(ErrorKind::Record, "remove source identity snapshot", error)
    })?;
    if current_hash != contract.source_manifest_sha256 {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "source workspace changed since the initial run",
        ));
    }

    let broad_stage = run_dir.join("stage");
    let after_manifest = workspace::manifest_tree(&broad_stage)?;
    let seed = optimizer::derive_changed_policy(
        &initial_manifest,
        &after_manifest,
        &contract.authorized_ceiling,
    )?;
    let strategy = match strategy {
        "hierarchical" => SearchStrategy::Hierarchical,
        "greedy" => SearchStrategy::Greedy,
        "random" => SearchStrategy::Random(0x4155544f43414745),
        _ => {
            return Err(AutoCageError::new(
                ErrorKind::Cli,
                "unknown optimizer strategy",
            ))
        }
    };
    let start = Instant::now();
    let mut sequence = 0usize;
    let ceiling = contract.authorized_ceiling.clone();
    journal::write_lifecycle(&run_dir, "tuning", None)?;
    let run_parent = run_dir.join("tuning/replays");
    create_private_run_directory(&run_parent)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "create replay directory", error))?;
    let result = optimizer::optimize(
        &ceiling,
        &seed,
        &initial_manifest,
        strategy,
        max_replays,
        |candidate| {
            if !candidate.is_subset_of(&ceiling)? {
                return Err(AutoCageError::new(
                    ErrorKind::Policy,
                    "candidate exceeds authorized ceiling",
                ));
            }
            let replay_dir = run_parent.join(format!("trial-{sequence:03}"));
            let trial_number = sequence;
            sequence += 1;
            journal::write_lifecycle(&run_dir, "tuning", Some(trial_number))?;
            let options = RunOptions {
                // Replays copy the contract-bound initial snapshot, never the
                // live checkout. The one-time source-drift check above still
                // rejects a changed checkout before search starts.
                workspace: run_dir.join("baseline"),
                run_dir: Some(replay_dir),
                timeout: Duration::from_secs(contract.timeout_seconds),
                verifier: Some(verifier.clone()),
                verifier_readonly: contract
                    .verifier_roots
                    .iter()
                    .map(|root| PathBuf::from(&root.relative_path))
                    .collect(),
                command: agent.clone(),
                policy: candidate.clone(),
                authorized_ceiling: Some(ceiling.clone()),
                accepted_proposal: None,
                record_contract: false,
            };
            // A trial's verifier and agent use argv captured in the private
            // contract; no agent-controlled result is interpreted as authorization.
            let replay_started = Instant::now();
            let replay =
                match run_with_policy(options, candidate.clone(), false, Some(&ceiling), None) {
                    Ok(replay) => replay,
                    Err(error) if error.kind == ErrorKind::Policy => {
                        return Ok(TrialObservation {
                            verifier_passed: false,
                            security_canaries_passed: false,
                            security_checks: vec![SecurityCheckRecord {
                                name: "authorized_ceiling_subset".to_owned(),
                                status: SecurityCheckStatus::Failed,
                                required_for_policy_promotion: true,
                                evidence: "candidate was rejected before execution".to_owned(),
                            }],
                            elapsed_millis: replay_started.elapsed().as_millis(),
                            classification: format!("invalid_policy: {}", error.message),
                        });
                    }
                    Err(error) => return Err(error),
                };
            let host_after = preflight::check()?;
            let runtime_after = contract::runtime_identity(&host_after)?;
            let trial_record = journal::validate_run(&replay.run_dir)?.record;
            let agent_exit = trial_record
                .pointer("/agent/exit_code")
                .and_then(serde_json::Value::as_i64);
            let verifier_exit = trial_record
                .pointer("/verifier/exit_code")
                .and_then(serde_json::Value::as_i64);
            let security_checks = trial_record
                .get("security_checks")
                .cloned()
                .and_then(|value| serde_json::from_value::<Vec<SecurityCheckRecord>>(value).ok())
                .unwrap_or_default();
            let required_checks = security_checks
                .iter()
                .filter(|check| check.required_for_policy_promotion)
                .collect::<Vec<_>>();
            let required_checks_passed = !required_checks.is_empty()
                && required_checks
                    .iter()
                    .all(|check| check.status == SecurityCheckStatus::Passed);
            let no_contract_drift = required_checks_passed
                && host_after == contract.host
                && runtime_after == contract.runtime
                && candidate.is_subset_of(&ceiling)?
                && serde_json::to_value(candidate).ok() == trial_record.get("policy").cloned()
                && !matches!(agent_exit, Some(96..=98));
            let outcome = trial_record
                .get("outcome")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("invalid_record");
            let failure_class = match outcome {
                "verified" => "verified".to_owned(),
                "agent_timed_out" => "agent_timeout".to_owned(),
                "verifier_timed_out" => "verifier_timeout".to_owned(),
                "verifier_failed" => {
                    format!("verifier_failed_exit_{}", verifier_exit.unwrap_or(-1))
                }
                "agent_failed" => format!("agent_failed_exit_{}", agent_exit.unwrap_or(-1)),
                other => format!("{other}_exit_{}", replay.exit_code),
            };
            let canary_classification = if required_checks_passed {
                "required_security_checks_passed"
            } else if verifier_exit.is_none() {
                "required_security_checks_not_tested"
            } else {
                "required_security_checks_failed_or_not_tested"
            };
            Ok(TrialObservation {
                verifier_passed: replay.verified,
                security_canaries_passed: no_contract_drift,
                security_checks,
                elapsed_millis: replay_started.elapsed().as_millis(),
                classification: format!(
                    "trial-{trial_number:03}:{failure_class}:{canary_classification}"
                ),
            })
        },
    )?;
    let mut result = result;
    result.optimization_elapsed_millis = start.elapsed().as_millis();
    write_optimizer_result(&result, &run_dir)?;
    journal::write_lifecycle(
        &run_dir,
        if result.status == "validated" {
            "tuned"
        } else {
            "inconclusive"
        },
        None,
    )?;
    journal::write_optimizer_seal(&run_dir)?;
    Ok(result)
}

fn validate_contract_runtime(contract: &RunContract) -> Result<()> {
    let current = preflight::check()?;
    let runtime = contract::runtime_identity(&current)?;
    if current != contract.host || runtime != contract.runtime {
        return Err(AutoCageError::new(
            ErrorKind::Record,
            "runtime identity changed since initial run",
        ));
    }
    Ok(())
}

fn write_optimizer_result(result: &OptimizationResult, run_dir: &Path) -> Result<()> {
    let path = run_dir.join("optimizer.json");
    let bytes = contract::json_bytes(result, "serialize optimizer result")?;
    contract::atomic_private_write(&path, &bytes, 0o400)
}

pub fn recover(run_dir: &Path) -> Result<usize> {
    let _run_lock = journal::lock(run_dir)?;
    journal::mark_interrupted(run_dir)
}

fn create_readonly_canary(run_dir: &Path) -> Result<(PathBuf, CommandSpec)> {
    let path = run_dir.join("readonly-canary");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "create readonly-mount canary", error)
        })?;
    file.write_all(b"AUTOCAGE-READONLY-CANARY-v1\n")
        .map_err(|error| {
            AutoCageError::io(ErrorKind::Record, "write readonly-mount canary", error)
        })?;
    file.sync_all().map_err(|error| {
        AutoCageError::io(ErrorKind::Record, "sync readonly-mount canary", error)
    })?;
    let script = "IFS= read -r value < /autocage-readonly-canary || exit 95; [ \"$value\" = 'AUTOCAGE-READONLY-CANARY-v1' ] || exit 95; if printf X >> /autocage-readonly-canary 2>/dev/null; then exit 94; fi; exit 0";
    Ok((
        path,
        CommandSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
        },
    ))
}

fn verifier_root_identities(
    snapshot: &workspace::WorkspaceSnapshot,
    roots: &[workspace::ProtectedRoot],
) -> Result<Vec<contract::VerifierRootIdentity>> {
    let paths = roots
        .iter()
        .map(|root| root.relative_path.clone())
        .collect::<Vec<_>>();
    verifier_root_identities_from_manifest(&snapshot.before_manifest, &paths)
}

fn verifier_root_identities_from_manifest(
    manifest: &[workspace::ManifestEntry],
    paths: &[String],
) -> Result<Vec<contract::VerifierRootIdentity>> {
    paths
        .iter()
        .map(|path| {
            let entries = manifest
                .iter()
                .filter(|entry| entry.path == *path || entry.path.starts_with(&format!("{path}/")))
                .collect::<Vec<_>>();
            if entries.is_empty() {
                return Err(AutoCageError::new(
                    ErrorKind::Record,
                    format!("verifier root is absent from the source snapshot: {path}"),
                ));
            }
            let bytes = serde_json::to_vec(&entries).map_err(|error| {
                AutoCageError::new(
                    ErrorKind::Record,
                    format!("serialize verifier-root identity: {error}"),
                )
            })?;
            Ok(contract::VerifierRootIdentity {
                relative_path: path.clone(),
                manifest_sha256: contract::hash_bytes(&bytes),
            })
        })
        .collect()
}

fn create_run_directory(explicit: Option<&Path>, workspace: &Path) -> Result<(String, PathBuf)> {
    let parent = if let Some(path) = explicit {
        let leaf = path.file_name().ok_or_else(|| {
            AutoCageError::new(ErrorKind::Stage, "--run-dir must name a new directory")
        })?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent.canonicalize().map_err(|error| {
            AutoCageError::io(ErrorKind::Stage, "resolve --run-dir parent", error)
        })?;
        let candidate = parent.join(leaf);
        if candidate.starts_with(workspace) {
            return Err(AutoCageError::new(
                ErrorKind::Stage,
                "--run-dir must be outside the source workspace",
            ));
        }
        if candidate.exists() {
            return Err(AutoCageError::new(
                ErrorKind::Stage,
                format!("run directory already exists: {}", candidate.display()),
            ));
        }
        (parent, Some(candidate))
    } else {
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
            })
            .ok_or_else(|| {
                AutoCageError::new(ErrorKind::Stage, "HOME or XDG_STATE_HOME is required")
            })?;
        let parent = state_root.join("autocage/runs");
        fs::create_dir_all(&parent).map_err(|error| {
            AutoCageError::io(ErrorKind::Stage, "create AutoCage run directory", error)
        })?;
        let parent = parent.canonicalize().map_err(|error| {
            AutoCageError::io(ErrorKind::Stage, "resolve AutoCage run directory", error)
        })?;
        if parent.starts_with(workspace) {
            return Err(AutoCageError::new(
                ErrorKind::Stage,
                "default run directory is inside the source workspace; set XDG_STATE_HOME outside it",
            ));
        }
        (parent, None)
    };

    for attempt in 0..4 {
        let timestamp = record::now_millis();
        let id = match explicit {
            Some(path) => path
                .file_name()
                .unwrap_or_else(|| OsStr::new("run"))
                .to_string_lossy()
                .into_owned(),
            None => format!("run-{timestamp}-{}-{attempt}", std::process::id()),
        };
        let path = if let Some(path) = &parent.1 {
            path.clone()
        } else {
            parent.0.join(&id)
        };
        match create_private_run_directory(&path) {
            Ok(()) => {
                return Ok((id, path));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && explicit.is_none() => {
                continue
            }
            Err(error) => {
                return Err(AutoCageError::io(
                    ErrorKind::Stage,
                    "create private run directory",
                    error,
                ))
            }
        }
    }
    Err(AutoCageError::new(
        ErrorKind::Stage,
        "could not allocate a unique run directory",
    ))
}

fn create_private_run_directory(path: &Path) -> io::Result<()> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "run path contains NUL"))?;
    let rc = unsafe { libc::mkdir(path_c.as_ptr(), 0o700) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn run_bounded(mut command: Command, timeout: Duration) -> Result<ProcessOutcome> {
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| AutoCageError::io(ErrorKind::Spawn, "start Bubblewrap command", error))?;
    let stdout_thread = drain(child.stdout.take(), io::stdout());
    let stderr_thread = drain(child.stderr.take(), io::stderr());
    let deadline = start + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            AutoCageError::io(ErrorKind::Spawn, "wait for Bubblewrap command", error)
        })? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            terminate_group(&mut child, Duration::from_millis(400));
            break child.wait().map_err(|error| {
                AutoCageError::io(ErrorKind::Spawn, "reap timed-out Bubblewrap command", error)
            })?;
        }
        thread::sleep(Duration::from_millis(20));
    };

    if timed_out {
        kill_group(child.id());
    }
    join_drain(stdout_thread);
    join_drain(stderr_thread);
    Ok(ProcessOutcome {
        exit_code: status_code(status),
        timed_out,
        elapsed_millis: start.elapsed().as_millis(),
    })
}

fn drain<R: Read + Send + 'static>(
    reader: Option<R>,
    mut destination: impl Write + Send + 'static,
) -> Option<thread::JoinHandle<()>> {
    let mut reader = reader?;
    Some(thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut destination);
        let _ = destination.flush();
    }))
}

fn join_drain(handle: Option<thread::JoinHandle<()>>) {
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

fn terminate_group(child: &mut Child, grace: Duration) {
    kill_group(child.id());
    let deadline = Instant::now() + grace;
    loop {
        if child.try_wait().ok().flatten().is_some() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    if child.try_wait().ok().flatten().is_none() {
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
        }
    }
}

fn kill_group(pid: u32) {
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

fn status_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

fn classify_outcome(
    agent: &ProcessOutcome,
    verifier: Option<&(CommandSpec, ProcessOutcome)>,
) -> String {
    if agent.timed_out {
        return "agent_timed_out".to_owned();
    }
    if agent.exit_code != 0 {
        return "agent_failed".to_owned();
    }
    match verifier {
        None => "agent_succeeded_unverified".to_owned(),
        Some((_, outcome)) if outcome.timed_out => "verifier_timed_out".to_owned(),
        Some((_, outcome)) if outcome.exit_code != 0 => "verifier_failed".to_owned(),
        Some(_) => "verified".to_owned(),
    }
}

fn outcome_exit_code(
    agent: &ProcessOutcome,
    verifier: Option<&(CommandSpec, ProcessOutcome)>,
) -> i32 {
    if agent.timed_out {
        124
    } else if agent.exit_code != 0 {
        agent.exit_code
    } else {
        match verifier {
            Some((_, outcome)) if outcome.timed_out => 124,
            Some((_, outcome)) if outcome.exit_code != 0 => 3,
            _ => 0,
        }
    }
}
