mod backend;
mod cli;
mod contract;
mod digest;
mod error;
mod journal;
mod optimizer;
mod policy;
mod preflight;
mod profile;
mod record;
mod runner;
mod workspace;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().and_then(|arg| arg.to_str()) == Some("__preflight_probe") {
        return match preflight::emit_child_probe() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("autocage preflight probe: {error}");
                ExitCode::from(1)
            }
        };
    }

    match cli::parse(args) {
        Ok(cli::Invocation::Help) => {
            print!("{}", cli::HELP);
            ExitCode::SUCCESS
        }
        Ok(cli::Invocation::Check) => match preflight::check() {
            Ok(facts) => {
                println!("AutoCage preflight passed");
                println!(
                    "Ubuntu {} on Linux {}; Bubblewrap {}",
                    facts.ubuntu_version, facts.kernel, facts.bubblewrap_version
                );
                println!("AppArmor profile: {}", facts.child_profile);
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("autocage check: {error}");
                ExitCode::from(2)
            }
        },
        Ok(cli::Invocation::Propose {
            workspace,
            workflow,
            command,
        }) => match profile::suggest(&workspace, workflow, &command) {
            Ok(proposal) => match serde_json::to_string_pretty(&proposal) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("autocage propose: serialize proposal: {error}");
                    ExitCode::from(2)
                }
            },
            Err(error) => {
                eprintln!("autocage propose: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Ok(cli::Invocation::Run(options)) => match runner::run(options) {
            Ok(result) => {
                println!("run directory: {}", result.run_dir.display());
                println!("record: {}", result.record_path.display());
                println!("patch: {}", result.patch_path.display());
                ExitCode::from(result.exit_code.clamp(0, 255) as u8)
            }
            Err(error) => {
                eprintln!("autocage run: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Ok(cli::Invocation::Tune {
            run_dir,
            workspace,
            agent,
            verifier,
            max_replays,
            strategy,
        }) => match runner::tune(
            &run_dir,
            &workspace,
            &agent,
            &verifier,
            max_replays,
            &strategy,
        ) {
            Ok(result) => {
                println!("optimizer: {} ({})", result.strategy, result.status);
                println!(
                    "weighted writable exposure: {} -> {} ({:.1}% reduction)",
                    result.ceiling_cost.weighted_writable_exposure,
                    result.best_cost.weighted_writable_exposure,
                    reduction(&result.ceiling_cost, &result.best_cost)
                );
                println!(
                    "authorized ceiling: {}",
                    describe_grants(&result.authorized_ceiling.write_grants)
                );
                println!(
                    "retained writes: {}",
                    describe_grants(&result.best_policy.write_grants)
                );
                println!(
                    "writable files: {}, recursive directory grants: {}, policy rules: {}",
                    result.best_cost.writable_regular_files,
                    result.best_cost.recursive_directory_grants,
                    result.best_cost.permission_rules
                );
                println!(
                    "replays: {} search + {} final validation = {}; elapsed: {} ms",
                    result.search_replays,
                    result.validation_replays,
                    result.total_replays,
                    result.optimization_elapsed_millis
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("autocage tune: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Ok(cli::Invocation::Recover { run_dir }) => match runner::recover(&run_dir) {
            Ok(removed) => {
                println!("marked incomplete run as interrupted; removed {removed} temporary evidence files; no policy is reusable");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("autocage recover: {error}");
                ExitCode::from(error.exit_code())
            }
        },
        Ok(cli::Invocation::Inspect { run_dir }) => inspect(&run_dir),
        Err(error) => {
            eprintln!("autocage: {error}\n\n{}", cli::HELP);
            ExitCode::from(2)
        }
    }
}

fn inspect(run_dir: &std::path::Path) -> ExitCode {
    let lifecycle = match journal::read_lifecycle(run_dir) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("autocage inspect: {error}");
            return ExitCode::from(2);
        }
    };
    if !["complete", "tuned", "inconclusive"].contains(&lifecycle.phase.as_str()) {
        let report = serde_json::json!({"lifecycle": lifecycle, "validation": "INCOMPLETE", "reusable_policy": false});
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("json value serializes")
        );
        return ExitCode::SUCCESS;
    }
    let validated = match journal::validate_run(run_dir) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("autocage inspect: invalid persisted evidence: {error}");
            return ExitCode::from(2);
        }
    };
    let report = serde_json::json!({
        "lifecycle": validated.lifecycle,
        "validation": "SEALED",
        "reusable_policy": validated.optimizer.is_some() && validated.lifecycle.phase == "tuned",
        "contract_sha256": validated.contract_sha256,
        "run_record_sha256": validated.record_sha256,
        "run": validated.record,
        "optimization": validated.optimizer
    });
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("autocage inspect: {error}");
            ExitCode::from(2)
        }
    }
}

fn reduction(ceiling: &optimizer::PolicyCost, candidate: &optimizer::PolicyCost) -> f64 {
    if ceiling.weighted_writable_exposure == 0 {
        0.0
    } else {
        (ceiling
            .weighted_writable_exposure
            .saturating_sub(candidate.weighted_writable_exposure) as f64
            / ceiling.weighted_writable_exposure as f64)
            * 100.0
    }
}

fn describe_grants(grants: &[policy::WriteGrant]) -> String {
    if grants.is_empty() {
        return "none".to_owned();
    }
    grants
        .iter()
        .map(|grant| match grant {
            policy::WriteGrant::FileContents(path) => format!("file-inode:{}", path.display()),
            policy::WriteGrant::DirectoryTree(path) => format!("directory-tree:{}", path.display()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
