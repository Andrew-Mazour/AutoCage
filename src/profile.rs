//! Experimental, deterministic pre-execution workflow profiles.
//!
//! A profile is a suggestion derived from an explicit workflow kind, the
//! staged source tree, and the exact command identity. It never authorizes a
//! write. The caller must separately provide the developer-approved ceiling.

use crate::cli::CommandSpec;
use crate::contract::{self, CommandIdentity};
use crate::error::{AutoCageError, ErrorKind, Result};
use crate::policy::{ExecutionPolicy, WriteGrant};
use crate::workspace;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;
pub const INFERENCE_RULESET: &str = "python-workflows-v1";
const MAX_PROFILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowKind {
    #[serde(rename = "python-test")]
    Test,
    #[serde(rename = "python-compileall")]
    Compileall,
    #[serde(rename = "python-wheel")]
    Wheel,
}

impl WorkflowKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "python-test" => Ok(Self::Test),
            "python-compileall" => Ok(Self::Compileall),
            "python-wheel" => Ok(Self::Wheel),
            _ => Err(profile_error(format!(
                "unsupported workflow {value:?}; supported workflows are python-test, python-compileall, and python-wheel"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRule {
    pub decision: String,
    pub rationale: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposal {
    pub schema_version: u32,
    pub ruleset: String,
    pub workflow: WorkflowKind,
    pub source_manifest_sha256: String,
    pub command: CommandIdentity,
    pub policy: ExecutionPolicy,
    /// These paths explain important project inputs. They are not a read
    /// whitelist: the current backend exposes the whole staged workspace as
    /// readonly unless a write grant is mounted over it.
    pub read_only_areas: Vec<String>,
    /// Bubblewrap creates a private tmpfs at /tmp for each child process.
    pub private_temporary_storage: Vec<String>,
    pub recognized_behavior: Vec<String>,
    pub unresolved_requirements: Vec<String>,
    pub rules: Vec<ProposalRule>,
}

#[derive(Debug)]
struct UnwrappedCommand<'a> {
    program: &'a OsStr,
    args: &'a [std::ffi::OsString],
    environment: Vec<(&'a str, &'a str)>,
}

pub fn suggest(
    workspace_root: &Path,
    workflow: WorkflowKind,
    command: &CommandSpec,
) -> Result<PolicyProposal> {
    let root = workspace_root.canonicalize().map_err(|error| {
        AutoCageError::io(ErrorKind::Policy, "resolve profile workspace", error)
    })?;
    if !root.is_dir() {
        return Err(profile_error("profile workspace must be a directory"));
    }
    let source_manifest_sha256 = workspace::source_manifest_hash(&root)?;
    let command_identity = contract::command_identity(command)?;
    let unwrapped = unwrap_env(command)?;
    let mut evidence = project_evidence(&root);
    let (policy, recognized_behavior, unresolved_requirements) = match workflow {
        WorkflowKind::Test => {
            let (recognized, unresolved) = recognize_python_test(&root, &unwrapped, &mut evidence)?;
            (ExecutionPolicy::new(Vec::new()), recognized, unresolved)
        }
        WorkflowKind::Compileall => {
            let (recognized, unresolved) =
                recognize_python_compileall(&root, &unwrapped, &mut evidence)?;
            (ExecutionPolicy::new(Vec::new()), recognized, unresolved)
        }
        WorkflowKind::Wheel => {
            let (grants, recognized, unresolved) =
                recognize_python_wheel(&root, &unwrapped, &mut evidence)?;
            (ExecutionPolicy::new(grants), recognized, unresolved)
        }
    };
    evidence.sort();
    evidence.dedup();
    let rules = if policy.write_grants.is_empty() {
        vec![ProposalRule {
            decision: "leave the staged workspace readonly".to_owned(),
            rationale: "recognized output is redirected to private /tmp; no workspace write grant is required by this profile".to_owned(),
            evidence: vec![INFERENCE_RULESET.to_owned()],
        }]
    } else {
        let output_paths = policy
            .write_grants
            .iter()
            .map(|grant| match grant {
                WriteGrant::DirectoryTree(path) => path.display().to_string(),
                WriteGrant::FileContents(path) => path.display().to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ");
        vec![ProposalRule {
            decision: "allow recursive writes only in the explicitly declared output directory".to_owned(),
            rationale: "the command names an existing workspace directory as --wheel-dir; the grant is limited to that directory and its descendants".to_owned(),
            evidence: vec![INFERENCE_RULESET.to_owned(), format!("explicit --wheel-dir output path: {output_paths}")],
        }]
    };

    Ok(PolicyProposal {
        schema_version: PROFILE_SCHEMA_VERSION,
        ruleset: INFERENCE_RULESET.to_owned(),
        workflow,
        source_manifest_sha256,
        command: command_identity,
        // Only the wheel workflow may receive one explicit existing output
        // directory grant. Other outputs must remain in private /tmp.
        policy,
        read_only_areas: evidence,
        private_temporary_storage: vec!["/tmp (private tmpfs per child)".to_owned()],
        recognized_behavior,
        unresolved_requirements,
        rules,
    })
}

/// Read a proposal as untrusted input. `validate_for_snapshot` must still be
/// called after AutoCage has staged the source and before it launches a child.
pub fn read(path: &Path) -> Result<(PolicyProposal, String)> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Policy, "inspect policy proposal", error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_PROFILE_BYTES
    {
        return Err(profile_error(
            "policy proposal must be a regular non-symlink file no larger than 1 MiB",
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| AutoCageError::io(ErrorKind::Policy, "read policy proposal", error))?;
    let proposal: PolicyProposal = serde_json::from_slice(&bytes)
        .map_err(|error| profile_error(format!("parse policy proposal: {error}")))?;
    validate_shape(&proposal)?;
    Ok((proposal, contract::hash_bytes(&bytes)))
}

pub fn validate_for_snapshot(
    proposal: &PolicyProposal,
    snapshot_root: &Path,
    command: &CommandSpec,
    authorized_ceiling: &ExecutionPolicy,
) -> Result<()> {
    validate_shape(proposal)?;
    let current = suggest(snapshot_root, proposal.workflow, command)?;
    if &current != proposal {
        return Err(profile_error(
            "policy proposal is stale, modified, or does not match this source snapshot and command",
        ));
    }
    if !proposal.policy.is_subset_of(authorized_ceiling)? {
        return Err(profile_error(
            "suggested policy exceeds the separately authorized developer ceiling",
        ));
    }
    Ok(())
}

fn validate_shape(proposal: &PolicyProposal) -> Result<()> {
    if proposal.schema_version != PROFILE_SCHEMA_VERSION || proposal.ruleset != INFERENCE_RULESET {
        return Err(profile_error(
            "unsupported policy proposal schema or ruleset",
        ));
    }
    proposal.policy.validate_global_invariants()?;
    if proposal.policy.normalize()? != proposal.policy {
        return Err(profile_error("proposal policy is not normalized"));
    }
    match proposal.workflow {
        WorkflowKind::Test | WorkflowKind::Compileall
            if !proposal.policy.write_grants.is_empty() =>
        {
            return Err(profile_error(
                "test and compileall workflows cannot grant workspace writes",
            ));
        }
        WorkflowKind::Wheel
            if proposal.policy.write_grants.len() > 1
                || proposal
                    .policy
                    .write_grants
                    .iter()
                    .any(|grant| !matches!(grant, WriteGrant::DirectoryTree(_))) =>
        {
            return Err(profile_error(
                "wheel workflow can suggest at most one recursive output-directory grant",
            ));
        }
        _ => {}
    }
    if proposal.private_temporary_storage != ["/tmp (private tmpfs per child)"] {
        return Err(profile_error(
            "invalid private temporary storage declaration",
        ));
    }
    Ok(())
}

fn unwrap_env(command: &CommandSpec) -> Result<UnwrappedCommand<'_>> {
    if basename(&command.program) != "env" {
        return Ok(UnwrappedCommand {
            program: &command.program,
            args: &command.args,
            environment: Vec::new(),
        });
    }
    let mut index = 0;
    let mut environment = Vec::new();
    while let Some(argument) = command.args.get(index) {
        let Some(value) = argument.to_str() else {
            return Err(profile_error(
                "env arguments must be UTF-8 for this profile",
            ));
        };
        if value == "--" {
            index += 1;
            break;
        }
        let Some((name, assigned)) = value.split_once('=') else {
            break;
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            break;
        }
        if environment.iter().any(|(existing, _)| *existing == name) {
            return Err(profile_error(format!(
                "env assignment {name} is repeated; its effective value is ambiguous"
            )));
        }
        environment.push((name, assigned));
        index += 1;
    }
    let program = command
        .args
        .get(index)
        .ok_or_else(|| profile_error("env command has no wrapped executable"))?;
    Ok(UnwrappedCommand {
        program,
        args: &command.args[index + 1..],
        environment,
    })
}

fn recognize_python_test(
    root: &Path,
    command: &UnwrappedCommand<'_>,
    evidence: &mut Vec<String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let args = utf8_args(command.args)?;
    let program_name = basename(command.program);
    let is_pytest = if program_name == "pytest" {
        true
    } else {
        is_python(program_name) && args.starts_with(&["-m", "pytest"])
    };
    if !is_pytest {
        return Err(profile_error(
            "python-test only recognizes pytest or python -m pytest commands",
        ));
    }
    if !has_private_pytest_cache(&args) {
        return Err(profile_error(
            "pytest must disable its cache provider or set -o cache_dir to an absolute /tmp path",
        ));
    }
    let source = choose_existing_directory(root, &["src", "lib"]);
    let tests = choose_existing_directory(root, &["tests", "testing", "test"]);
    if let Some(path) = source {
        evidence.push(path);
    }
    if let Some(path) = tests {
        evidence.push(path);
    }
    for config in ["pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg"] {
        if root.join(config).is_file() {
            evidence.push(config.to_owned());
        }
    }
    if !evidence
        .iter()
        .any(|path| path == "tests" || path == "testing" || path == "test")
    {
        evidence.push(".".to_owned());
    }
    Ok((
        vec!["pytest cache is disabled or directed to /tmp".to_owned()],
        vec![
            "pytest plugins and test code may have additional output behavior not inferred by this ruleset".to_owned(),
            "network-dependent tests remain blocked by the runner's private network namespace".to_owned(),
        ],
    ))
}

fn recognize_python_compileall(
    root: &Path,
    command: &UnwrappedCommand<'_>,
    evidence: &mut Vec<String>,
) -> Result<(Vec<String>, Vec<String>)> {
    let args = utf8_args(command.args)?;
    if !is_python(basename(command.program)) || args.len() < 4 || args[0..2] != ["-m", "compileall"]
    {
        return Err(profile_error(
            "python-compileall only recognizes python -m compileall -q TARGET...",
        ));
    }
    if args[2] != "-q" || args.len() < 4 {
        return Err(profile_error(
            "python-compileall requires the supported -q form and explicit targets",
        ));
    }
    let prefix = command
        .environment
        .iter()
        .find_map(|(name, value)| (*name == "PYTHONPYCACHEPREFIX").then_some(*value))
        .ok_or_else(|| {
            profile_error("compileall must set PYTHONPYCACHEPREFIX to private /tmp storage")
        })?;
    validate_private_tmp(prefix)?;
    for target in &args[3..] {
        let relative = validate_workspace_relative(target)?;
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Policy,
                format!("inspect compileall target {target}"),
                error,
            )
        })?;
        if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
            return Err(profile_error(
                "compileall targets must be existing regular files or directories, not symlinks",
            ));
        }
        evidence.push(relative.to_string_lossy().into_owned());
    }
    evidence.sort();
    Ok((
        vec!["compileall bytecode cache is redirected under private /tmp".to_owned()],
        vec![
            "only the declared compileall targets are analyzed; arbitrary build hooks are not inferred".to_owned(),
        ],
    ))
}

fn recognize_python_wheel(
    root: &Path,
    command: &UnwrappedCommand<'_>,
    evidence: &mut Vec<String>,
) -> Result<(Vec<WriteGrant>, Vec<String>, Vec<String>)> {
    let args = utf8_args(command.args)?;
    if !is_python(basename(command.program))
        || args.len() < 5
        || args[0..3] != ["-m", "pip", "wheel"]
    {
        return Err(profile_error(
            "python-wheel only recognizes python -m pip wheel with a local project input",
        ));
    }
    if !args.contains(&"--no-deps") || !args.contains(&"--no-build-isolation") {
        return Err(profile_error(
            "python-wheel requires --no-deps and --no-build-isolation so dependencies are not fetched",
        ));
    }
    let mut output = None;
    let mut index = 3;
    while index < args.len() {
        let argument = args[index];
        if argument == "--wheel-dir" {
            output = args.get(index + 1).copied();
            index += 2;
        } else if let Some(value) = argument.strip_prefix("--wheel-dir=") {
            output = Some(value);
            index += 1;
        } else {
            index += 1;
        }
    }
    let output =
        output.ok_or_else(|| profile_error("python-wheel requires an explicit --wheel-dir"))?;
    let output_grants = if output == "/tmp" || output.starts_with("/tmp/") {
        validate_private_tmp(output)?;
        Vec::new()
    } else {
        let relative = validate_workspace_relative(output)?;
        if relative == Path::new(".") {
            return Err(profile_error(
                "python-wheel may not grant the workspace root as its output directory",
            ));
        }
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Policy,
                "inspect declared wheel output directory",
                error,
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(profile_error(
                "workspace wheel output must be an existing non-symlink directory",
            ));
        }
        vec![WriteGrant::DirectoryTree(relative)]
    };
    if !args.iter().any(|argument| *argument == ".")
        || !(root.join("pyproject.toml").is_file() || root.join("setup.py").is_file())
    {
        return Err(profile_error(
            "python-wheel input must be the current local project with a Python build manifest",
        ));
    }
    evidence.push("pyproject.toml or setup.py".to_owned());
    let recognized_output = if output_grants.is_empty() {
        "wheel artifacts are written under private /tmp".to_owned()
    } else {
        format!("wheel artifacts are confined to the existing workspace directory {output}")
    };
    Ok((
        output_grants,
        vec![recognized_output],
        vec![
            "the selected PEP 517 or legacy build backend is not analyzed and may be denied if it writes inside the readonly workspace".to_owned(),
            "dependencies and build isolation are disabled; all undeclared backend inputs must already exist in the guest runtime".to_owned(),
        ],
    ))
}

fn project_evidence(root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    for directory in ["src", "lib", "tests", "testing", "test"] {
        if root.join(directory).is_dir() {
            paths.push(directory.to_owned());
        }
    }
    for config in ["pyproject.toml", "pytest.ini", "tox.ini", "setup.cfg"] {
        if root.join(config).is_file() {
            paths.push(config.to_owned());
        }
    }
    paths
}

fn choose_existing_directory(root: &Path, choices: &[&str]) -> Option<String> {
    choices
        .iter()
        .find(|path| root.join(path).is_dir())
        .map(|path| (*path).to_owned())
}

fn has_private_pytest_cache(args: &[&str]) -> bool {
    let plugins = args
        .windows(2)
        .filter(|pair| pair[0] == "-p")
        .map(|pair| pair[1])
        .collect::<Vec<_>>();
    if plugins.contains(&"no:cacheprovider") && !plugins.contains(&"cacheprovider") {
        return true;
    }
    let cache_dirs = args
        .windows(2)
        .filter(|pair| pair[0] == "-o")
        .filter_map(|pair| pair[1].strip_prefix("cache_dir="))
        .collect::<Vec<_>>();
    cache_dirs
        .last()
        .is_some_and(|path| validate_private_tmp(path).is_ok())
}

fn validate_private_tmp(value: &str) -> Result<()> {
    let path = Path::new(value);
    if !path.is_absolute()
        || !(value == "/tmp" || value.starts_with("/tmp/"))
        || value.contains("//")
        || value.ends_with('/')
        || value.contains("/./")
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(profile_error(
            "temporary output must remain under private /tmp",
        ));
    }
    Ok(())
}

fn validate_workspace_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(profile_error(
            "workflow target must be a normalized workspace-relative path",
        ));
    }
    Ok(path.to_path_buf())
}

fn utf8_args(args: &[std::ffi::OsString]) -> Result<Vec<&str>> {
    args.iter()
        .map(|argument| {
            argument
                .to_str()
                .ok_or_else(|| profile_error("workflow arguments must be UTF-8"))
        })
        .collect()
}

fn basename(value: &OsStr) -> &str {
    Path::new(value)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
}

fn is_python(value: &str) -> bool {
    value == "python"
        || value
            .strip_prefix("python")
            .and_then(|suffix| suffix.chars().next())
            .is_some_and(|character| character.is_ascii_digit() || character == '.')
}

fn profile_error(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Policy, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "autocage-profile-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(path.join("src")).unwrap();
        fs::create_dir(path.join("tests")).unwrap();
        fs::write(path.join("pyproject.toml"), "[tool.pytest.ini_options]\n").unwrap();
        path
    }

    fn pytest_command() -> CommandSpec {
        CommandSpec {
            program: "/usr/bin/env".into(),
            args: [
                "PYTHONPATH=/workspace/src",
                "/usr/bin/python3",
                "-m",
                "pytest",
                "tests",
                "-q",
                "-o",
                "cache_dir=/tmp/autocage-pytest-cache",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        }
    }

    #[test]
    fn pytest_proposal_is_readonly_and_reports_unresolved_plugin_behavior() {
        let root = temp_dir();
        let proposal = suggest(&root, WorkflowKind::Test, &pytest_command()).unwrap();
        assert!(proposal.policy.write_grants.is_empty());
        assert_eq!(proposal.read_only_areas, ["pyproject.toml", "src", "tests"]);
        assert!(proposal
            .recognized_behavior
            .iter()
            .any(|item| item.contains("cache")));
        assert!(!proposal.unresolved_requirements.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pytest_without_private_cache_is_rejected_instead_of_widened() {
        let root = temp_dir();
        let mut command = pytest_command();
        command.args.truncate(5);
        assert!(suggest(&root, WorkflowKind::Test, &command)
            .unwrap_err()
            .message
            .contains("cache"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compileall_requires_private_prefix_and_normalized_targets() {
        let root = temp_dir();
        let command = CommandSpec {
            program: "/usr/bin/env".into(),
            args: [
                "PYTHONPYCACHEPREFIX=/tmp/autocage-pycache",
                "/usr/bin/python3",
                "-m",
                "compileall",
                "-q",
                "src",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        };
        let proposal = suggest(&root, WorkflowKind::Compileall, &command).unwrap();
        assert!(proposal.policy.write_grants.is_empty());
        assert!(suggest(
            &root,
            WorkflowKind::Compileall,
            &CommandSpec {
                program: "/usr/bin/env".into(),
                args: ["/usr/bin/python3", "-m", "compileall", "-q", "src"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            }
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wheel_profile_requires_local_offline_build_and_private_output() {
        let root = temp_dir();
        let command = CommandSpec {
            program: "/usr/bin/env".into(),
            args: [
                "PYTHONPATH=/usr/local/lib/autocage-m3-site-v2",
                "/usr/bin/python3",
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                "/tmp/autocage-wheels",
                ".",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        };
        let proposal = suggest(&root, WorkflowKind::Wheel, &command).unwrap();
        assert!(proposal.policy.write_grants.is_empty());
        assert!(suggest(
            &root,
            WorkflowKind::Wheel,
            &CommandSpec {
                program: "/usr/bin/python3".into(),
                args: ["-m", "pip", "wheel", "--no-deps", "."]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            }
        )
        .is_err());

        fs::create_dir(root.join("dist")).unwrap();
        let workspace_output = CommandSpec {
            program: "/usr/bin/env".into(),
            args: [
                "PYTHONPATH=/usr/local/lib/autocage-m3-site-v2",
                "/usr/bin/python3",
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                "dist",
                ".",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        };
        let proposal = suggest(&root, WorkflowKind::Wheel, &workspace_output).unwrap();
        let expected = ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from("dist"))]);
        assert_eq!(proposal.policy, expected);
        assert!(!proposal.read_only_areas.contains(&"dist".to_owned()));
        assert!(proposal.rules[0].decision.contains("output directory"));
        validate_for_snapshot(&proposal, &root, &workspace_output, &expected).unwrap();
        assert!(validate_for_snapshot(
            &proposal,
            &root,
            &workspace_output,
            &ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from(
                "pyproject.toml"
            ))]),
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn proposal_rejects_source_command_and_artifact_changes() {
        let root = temp_dir();
        let proposal = suggest(&root, WorkflowKind::Test, &pytest_command()).unwrap();
        validate_for_snapshot(
            &proposal,
            &root,
            &pytest_command(),
            &ExecutionPolicy::baseline(),
        )
        .unwrap();
        let changed_command = CommandSpec {
            program: "/usr/bin/env".into(),
            args: [
                "PYTHONPATH=/workspace/src",
                "/usr/bin/python3",
                "-m",
                "pytest",
                "tests",
                "-q",
                "-o",
                "cache_dir=/tmp/changed-output",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
        };
        assert!(validate_for_snapshot(
            &proposal,
            &root,
            &changed_command,
            &ExecutionPolicy::baseline(),
        )
        .is_err());
        let mut changed_artifact = proposal.clone();
        changed_artifact.rules[0].rationale = "modified artifact".to_owned();
        assert!(validate_for_snapshot(
            &changed_artifact,
            &root,
            &pytest_command(),
            &ExecutionPolicy::baseline(),
        )
        .is_err());
        assert!(!serde_json::to_string(&proposal)
            .unwrap()
            .contains("autocage-pytest-cache"));
        fs::write(root.join("src/value.py"), "changed\n").unwrap();
        assert!(validate_for_snapshot(
            &proposal,
            &root,
            &pytest_command(),
            &ExecutionPolicy::baseline(),
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
