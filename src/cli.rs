use crate::error::{AutoCageError, ErrorKind, Result};
use crate::policy::{ExecutionPolicy, WriteGrant};
use crate::profile::WorkflowKind;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

pub const HELP: &str = concat!(
    "AutoCage — fail-closed isolated command runner\n\n",
    "Usage:\n",
    "  autocage check\n",
    "  autocage propose --workspace PATH --workflow python-test|python-compileall|python-wheel -- PROGRAM [ARG ...]\n",
    "  autocage run --workspace PATH [--run-dir PATH] [--timeout-seconds N] \\\n",
    "      [--verify-command PROGRAM] [--verify-arg ARG ...] \\\n",
    "      [--verify-readonly REL_PATH ...] [--read-only | --ceiling-dir REL | --ceiling-file REL] \\\n",
    "      [--accept-proposal FILE] \\\n",
    "      [--record-contract] -- PROGRAM [ARG ...]\n",
    "  autocage tune RUN_DIR --workspace PATH --agent-command PROGRAM [--agent-arg ARG ...] \\\n",
    "      --verify-command PROGRAM [--verify-arg ARG ...] [--max-replays N] [--strategy hierarchical|greedy|random]\n",
    "  autocage recover RUN_DIR\n",
    "  autocage inspect RUN_DIR\n\n",
    "The command after -- runs in a copied, writable workspace with no outbound network.\n",
    "Readonly verifier roots are snapshotted from the original workspace and overmounted for verifier runs.\n",
    "Only an explicitly provided verifier is run after a successful command.\n",
    "`propose` emits an experimental deterministic suggestion; it grants no authority. `run --accept-proposal` requires an explicit ceiling.\n",
    "--record-contract stores command identities, not argument values, and requires at least one --verify-readonly root.\n",
    "For reusable tuning evidence, declare every workspace-resident verifier code/config/test root read-only. `tune` requires the exact workspace, commands, and arguments again.\n",
);

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub workspace: PathBuf,
    pub run_dir: Option<PathBuf>,
    pub timeout: Duration,
    pub verifier: Option<CommandSpec>,
    pub verifier_readonly: Vec<PathBuf>,
    pub command: CommandSpec,
    /// Effective policy for a regular run. For an accepted proposal, the
    /// effective policy is loaded and revalidated by the runner.
    pub policy: ExecutionPolicy,
    pub authorized_ceiling: Option<ExecutionPolicy>,
    pub accepted_proposal: Option<PathBuf>,
    pub record_contract: bool,
}

#[derive(Debug, Clone)]
pub enum Invocation {
    Help,
    Check,
    Propose {
        workspace: PathBuf,
        workflow: WorkflowKind,
        command: CommandSpec,
    },
    Run(RunOptions),
    Tune {
        run_dir: PathBuf,
        workspace: PathBuf,
        agent: CommandSpec,
        verifier: CommandSpec,
        max_replays: usize,
        strategy: String,
    },
    Recover {
        run_dir: PathBuf,
    },
    Inspect {
        run_dir: PathBuf,
    },
}

pub fn parse(args: Vec<OsString>) -> Result<Invocation> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return Ok(Invocation::Help);
    }
    match args[0].to_str() {
        Some("check") if args.len() == 1 => Ok(Invocation::Check),
        Some("propose") => parse_propose(&args[1..]),
        Some("run") => parse_run(&args[1..]),
        Some("tune") => parse_tune(&args[1..]),
        Some("recover") if args.len() == 2 => Ok(Invocation::Recover {
            run_dir: PathBuf::from(&args[1]),
        }),
        Some("inspect") if args.len() == 2 => Ok(Invocation::Inspect {
            run_dir: PathBuf::from(&args[1]),
        }),
        _ => Err(AutoCageError::new(
            ErrorKind::Cli,
            "expected `check` or `run`",
        )),
    }
}

fn parse_propose(args: &[OsString]) -> Result<Invocation> {
    let mut workspace = None;
    let mut workflow = None;
    let mut separator = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--" {
            separator = Some(index);
            break;
        }
        let flag = args[index].to_str().ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, "option names must be valid UTF-8")
        })?;
        let value = args.get(index + 1).ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, format!("missing value for {flag}"))
        })?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--workflow" => {
                let text = value
                    .to_str()
                    .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "workflow must be UTF-8"))?;
                workflow = Some(WorkflowKind::parse(text)?);
            }
            _ => {
                return Err(AutoCageError::new(
                    ErrorKind::Cli,
                    format!("unknown propose option {flag:?}"),
                ))
            }
        }
        index += 2;
    }
    let separator = separator.ok_or_else(|| {
        AutoCageError::new(ErrorKind::Cli, "propose requires `-- PROGRAM [ARG ...]`")
    })?;
    let command = &args[separator + 1..];
    if command.is_empty() || command[0].is_empty() {
        return Err(AutoCageError::new(
            ErrorKind::Cli,
            "workflow command is empty",
        ));
    }
    Ok(Invocation::Propose {
        workspace: workspace
            .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "propose requires --workspace"))?,
        workflow: workflow
            .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "propose requires --workflow"))?,
        command: CommandSpec {
            program: command[0].clone(),
            args: command[1..].to_vec(),
        },
    })
}

fn parse_run(args: &[OsString]) -> Result<Invocation> {
    let mut workspace = None;
    let mut run_dir = None;
    let mut timeout = Duration::from_secs(300);
    let mut verifier_program: Option<OsString> = None;
    let mut verifier_args = Vec::new();
    let mut verifier_readonly = Vec::new();
    let mut grants = Vec::new();
    let mut has_explicit_ceiling = false;
    let mut explicit_read_only = false;
    let mut accepted_proposal = None;
    let mut record_contract = false;
    let mut separator = None;
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--" {
            separator = Some(index);
            break;
        }
        let flag = args[index].to_str().ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, "option names must be valid UTF-8")
        })?;
        index += 1;
        if flag == "--record-contract" || flag == "--read-only" {
            if flag == "--record-contract" {
                record_contract = true;
            } else {
                explicit_read_only = true;
                has_explicit_ceiling = true;
            }
            continue;
        }
        let value = args.get(index).ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, format!("missing value for {flag}"))
        })?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--run-dir" => run_dir = Some(PathBuf::from(value)),
            "--accept-proposal" => accepted_proposal = Some(PathBuf::from(value)),
            "--timeout-seconds" => {
                let raw = value.to_str().ok_or_else(|| {
                    AutoCageError::new(ErrorKind::Cli, "timeout must be an integer")
                })?;
                let seconds = raw.parse::<u64>().map_err(|_| {
                    AutoCageError::new(ErrorKind::Cli, "timeout must be a positive integer")
                })?;
                if seconds == 0 || seconds > 24 * 60 * 60 {
                    return Err(AutoCageError::new(
                        ErrorKind::Cli,
                        "timeout must be between 1 and 86400 seconds",
                    ));
                }
                timeout = Duration::from_secs(seconds);
            }
            "--verify-command" => verifier_program = Some(value.clone()),
            "--verify-arg" => verifier_args.push(value.clone()),
            "--verify-readonly" => verifier_readonly.push(PathBuf::from(value)),
            "--ceiling-dir" => {
                grants.push(WriteGrant::DirectoryTree(PathBuf::from(value)));
                has_explicit_ceiling = true;
            }
            "--ceiling-file" => {
                grants.push(WriteGrant::FileContents(PathBuf::from(value)));
                has_explicit_ceiling = true;
            }
            _ => {
                return Err(AutoCageError::new(
                    ErrorKind::Cli,
                    format!("unknown run option {flag:?}"),
                ))
            }
        }
        index += 1;
    }

    let separator = separator
        .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "run requires `-- PROGRAM [ARG ...]`"))?;
    let command = args[separator + 1..].to_vec();
    if command.is_empty() || command[0].is_empty() {
        return Err(AutoCageError::new(ErrorKind::Cli, "agent command is empty"));
    }
    if verifier_program.is_none() && (!verifier_args.is_empty() || !verifier_readonly.is_empty()) {
        return Err(AutoCageError::new(
            ErrorKind::Cli,
            "--verify-arg and --verify-readonly require --verify-command",
        ));
    }
    let workspace =
        workspace.ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "--workspace is required"))?;
    let verifier = verifier_program.map(|program| CommandSpec {
        program,
        args: verifier_args,
    });
    if explicit_read_only && !grants.is_empty() {
        return Err(AutoCageError::new(
            ErrorKind::Cli,
            "--read-only cannot be combined with write-ceiling grants",
        ));
    }
    let ceiling = if has_explicit_ceiling {
        ExecutionPolicy::new(grants).normalize()?
    } else {
        ExecutionPolicy::baseline()
    };
    if accepted_proposal.is_some() && !has_explicit_ceiling {
        return Err(AutoCageError::new(
            ErrorKind::Policy,
            "--accept-proposal requires an explicit developer ceiling via --read-only, --ceiling-dir, or --ceiling-file",
        ));
    }
    let (policy, authorized_ceiling) = if accepted_proposal.is_some() {
        (ExecutionPolicy::new(Vec::new()), Some(ceiling))
    } else {
        (ceiling, None)
    };
    Ok(Invocation::Run(RunOptions {
        workspace,
        run_dir,
        timeout,
        verifier,
        verifier_readonly,
        command: CommandSpec {
            program: command[0].clone(),
            args: command[1..].to_vec(),
        },
        policy,
        authorized_ceiling,
        accepted_proposal,
        record_contract,
    }))
}

fn parse_tune(args: &[OsString]) -> Result<Invocation> {
    let run_dir = args
        .first()
        .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "tune requires a run directory"))?;
    let mut max_replays = crate::optimizer::DEFAULT_BUDGET;
    let mut strategy = "hierarchical".to_owned();
    let mut workspace = None;
    let mut agent_program = None;
    let mut agent_args = Vec::new();
    let mut verifier_program = None;
    let mut verifier_args = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let flag = args[index].to_str().ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, "option names must be valid UTF-8")
        })?;
        let value = args.get(index + 1).ok_or_else(|| {
            AutoCageError::new(ErrorKind::Cli, format!("missing value for {flag}"))
        })?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--agent-command" => agent_program = Some(value.clone()),
            "--agent-arg" => agent_args.push(value.clone()),
            "--verify-command" => verifier_program = Some(value.clone()),
            "--verify-arg" => verifier_args.push(value.clone()),
            "--max-replays" => {
                max_replays = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| {
                        AutoCageError::new(ErrorKind::Cli, "max replays must be a positive integer")
                    })?;
                if !(4..=100).contains(&max_replays) {
                    return Err(AutoCageError::new(ErrorKind::Cli, "max replays must be between 4 and 100 (three are reserved for final validation)"));
                }
            }
            "--strategy" => {
                strategy = value
                    .to_str()
                    .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "strategy must be UTF-8"))?
                    .to_owned();
                if !["hierarchical", "greedy", "random"].contains(&strategy.as_str()) {
                    return Err(AutoCageError::new(
                        ErrorKind::Cli,
                        "strategy must be hierarchical, greedy, or random",
                    ));
                }
            }
            _ => {
                return Err(AutoCageError::new(
                    ErrorKind::Cli,
                    format!("unknown tune option {flag:?}"),
                ))
            }
        }
        index += 2;
    }
    let workspace =
        workspace.ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "tune requires --workspace"))?;
    let agent_program = agent_program
        .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "tune requires --agent-command"))?;
    let verifier_program = verifier_program
        .ok_or_else(|| AutoCageError::new(ErrorKind::Cli, "tune requires --verify-command"))?;
    Ok(Invocation::Tune {
        run_dir: PathBuf::from(run_dir),
        workspace,
        agent: CommandSpec {
            program: agent_program,
            args: agent_args,
        },
        verifier: CommandSpec {
            program: verifier_program,
            args: verifier_args,
        },
        max_replays,
        strategy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn command_arguments_after_separator_are_opaque() {
        let parsed = parse(strings(&[
            "run",
            "--workspace",
            "repo with spaces",
            "--verify-command",
            "pytest",
            "--verify-arg",
            "-q",
            "--verify-readonly",
            "tests",
            "--",
            "script",
            "--flag",
            "task with spaces",
        ]))
        .expect("valid command");
        let Invocation::Run(options) = parsed else {
            panic!("expected run");
        };
        assert_eq!(options.workspace, PathBuf::from("repo with spaces"));
        assert_eq!(options.command.program, "script");
        assert_eq!(
            options.command.args,
            strings(&["--flag", "task with spaces"])
        );
        assert_eq!(options.verifier.expect("verifier").args, strings(&["-q"]));
        assert_eq!(options.verifier_readonly, vec![PathBuf::from("tests")]);
    }

    #[test]
    fn proposal_command_requires_a_supported_workflow_and_exact_command() {
        let parsed = parse(strings(&[
            "propose",
            "--workspace",
            "repo",
            "--workflow",
            "python-test",
            "--",
            "python3",
            "-m",
            "pytest",
        ]))
        .unwrap();
        let Invocation::Propose {
            workspace,
            workflow,
            command,
        } = parsed
        else {
            panic!("expected proposal invocation")
        };
        assert_eq!(workspace, PathBuf::from("repo"));
        assert_eq!(workflow, WorkflowKind::Test);
        assert_eq!(command.program, "python3");
        assert_eq!(command.args, strings(&["-m", "pytest"]));

        assert!(parse(strings(&[
            "propose",
            "--workspace",
            "repo",
            "--workflow",
            "natural-language",
            "--",
            "python3",
        ]))
        .is_err());
    }

    #[test]
    fn accepting_a_proposal_requires_a_separate_explicit_ceiling() {
        assert!(parse(strings(&[
            "run",
            "--workspace",
            "repo",
            "--accept-proposal",
            "profile.json",
            "--",
            "true",
        ]))
        .is_err());

        let Invocation::Run(options) = parse(strings(&[
            "run",
            "--workspace",
            "repo",
            "--accept-proposal",
            "profile.json",
            "--ceiling-dir",
            ".",
            "--",
            "true",
        ]))
        .unwrap() else {
            panic!("expected run invocation")
        };
        assert!(options.policy.write_grants.is_empty());
        assert_eq!(
            options.authorized_ceiling.unwrap().write_grants,
            vec![WriteGrant::DirectoryTree(PathBuf::from("."))]
        );
    }

    #[test]
    fn verifier_args_require_a_verifier_program() {
        let error = parse(strings(&[
            "run",
            "--workspace",
            ".",
            "--verify-arg",
            "-q",
            "--",
            "true",
        ]))
        .expect_err("must reject verifier args without a program");
        assert!(error.message.contains("require --verify-command"));
    }

    #[test]
    fn missing_required_separator_is_rejected() {
        let error = parse(strings(&["run", "--workspace", ".", "true"]))
            .expect_err("must require argument boundary");
        assert!(!error.message.is_empty());
    }

    #[test]
    fn empty_program_is_rejected() {
        let error = parse(vec![
            OsString::from("run"),
            OsString::from("--workspace"),
            OsString::from("."),
            OsString::from("--"),
            OsString::new(),
        ])
        .expect_err("must reject empty program");
        assert!(error.message.contains("empty"));
    }

    #[test]
    fn only_known_option_names_are_accepted() {
        let error = parse(strings(&[
            "run",
            "--workspace",
            ".",
            "--mystery",
            "x",
            "--",
            "true",
        ]))
        .expect_err("must reject unknown option");
        assert!(error.message.contains("unknown run option"));
    }

    #[test]
    fn option_values_can_start_with_dash() {
        let parsed = parse(strings(&[
            "run",
            "--workspace",
            ".",
            "--verify-command",
            "pytest",
            "--verify-arg",
            "-q",
            "--",
            "true",
        ]))
        .expect("-q is a value, not an option");
        let Invocation::Run(options) = parsed else {
            panic!("expected run");
        };
        assert_eq!(options.verifier.expect("verifier").args, strings(&["-q"]));
    }

    #[test]
    fn read_only_policy_is_explicit_and_cannot_overlap_write_grants() {
        let Invocation::Run(options) = parse(strings(&[
            "run",
            "--workspace",
            ".",
            "--read-only",
            "--",
            "true",
        ]))
        .unwrap() else {
            panic!("expected run")
        };
        assert!(options.policy.write_grants.is_empty());
        assert!(parse(strings(&[
            "run",
            "--workspace",
            ".",
            "--read-only",
            "--ceiling-dir",
            "src",
            "--",
            "true",
        ]))
        .is_err());
    }

    #[test]
    fn tune_replay_budget_reserves_final_validation_runs() {
        let Invocation::Tune {
            workspace,
            agent,
            verifier,
            max_replays,
            strategy,
            ..
        } = parse(strings(&[
            "tune",
            "/tmp/run",
            "--workspace",
            "/tmp/project",
            "--agent-command",
            "python3",
            "--agent-arg",
            "agent.py",
            "--verify-command",
            "pytest",
            "--verify-arg",
            "-q",
            "--max-replays",
            "12",
            "--strategy",
            "random",
        ]))
        .unwrap()
        else {
            panic!("expected tune")
        };
        assert_eq!(max_replays, 12);
        assert_eq!(strategy, "random");
        assert_eq!(workspace, PathBuf::from("/tmp/project"));
        assert_eq!(agent.program, "python3");
        assert_eq!(agent.args, strings(&["agent.py"]));
        assert_eq!(verifier.program, "pytest");
        assert_eq!(verifier.args, strings(&["-q"]));
        assert!(parse(strings(&[
            "tune",
            "/tmp/run",
            "--workspace",
            "/tmp/project",
            "--agent-command",
            "true",
            "--verify-command",
            "true",
            "--max-replays",
            "3"
        ]))
        .is_err());
    }
}
