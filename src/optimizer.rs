//! Bounded, verifier-guided narrowing of filesystem write grants.
//!
//! This module never creates authority: all proposals are checked as subsets
//! of the developer-supplied ceiling before the runner is called.

use crate::error::{AutoCageError, ErrorKind, Result};
use crate::policy::{path_is_same_or_child, ExecutionPolicy, WriteGrant};
use crate::record::{SecurityCheckRecord, SecurityCheckStatus};
use crate::workspace::{EntryKind, ManifestEntry};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const COST_SCHEMA: &str = "weighted-write-surface-v1";
pub const DEFAULT_BUDGET: usize = 12;
const DIRECTORY_ENTRY_WEIGHT: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchStrategy {
    Hierarchical,
    Greedy,
    Random(u64),
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyCost {
    pub schema: &'static str,
    pub weighted_writable_exposure: u64,
    pub writable_regular_files: usize,
    pub writable_directories: usize,
    pub recursive_directory_grants: usize,
    pub permission_rules: usize,
    pub file_weight_total: u64,
    pub directory_entry_weight_total: u64,
}

#[derive(Debug, Clone)]
pub struct TrialObservation {
    pub verifier_passed: bool,
    pub security_canaries_passed: bool,
    pub security_checks: Vec<SecurityCheckRecord>,
    pub elapsed_millis: u128,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrialRecord {
    pub policy: ExecutionPolicy,
    pub cost: PolicyCost,
    pub passed: bool,
    pub security_canaries_passed: bool,
    pub security_checks: Vec<SecurityCheckRecord>,
    pub elapsed_millis: u128,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OptimizationResult {
    pub strategy: String,
    pub status: String,
    pub authorized_ceiling: ExecutionPolicy,
    pub best_policy: ExecutionPolicy,
    pub ceiling_cost: PolicyCost,
    pub best_cost: PolicyCost,
    pub search_replays: usize,
    pub validation_replays: usize,
    pub total_replays: usize,
    pub optimization_elapsed_millis: u128,
    pub trials: Vec<TrialRecord>,
    pub rejected_trials: usize,
}

pub fn derive_changed_policy(
    before: &[ManifestEntry],
    after: &[ManifestEntry],
    ceiling: &ExecutionPolicy,
) -> Result<ExecutionPolicy> {
    let old = before
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let new = after
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let paths = old
        .keys()
        .chain(new.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut grants = Vec::new();
    for path in paths {
        let previous = old.get(path);
        let current = new.get(path);
        if previous == current {
            continue;
        }
        match (previous, current) {
            (Some(before_entry), Some(after_entry))
                if before_entry.kind == EntryKind::RegularFile
                    && after_entry.kind == EntryKind::RegularFile =>
            {
                grants.push(WriteGrant::FileContents(PathBuf::from(path)));
            }
            _ => {
                let mut parent = Path::new(path)
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                while parent != Path::new(".")
                    && !old
                        .get(parent.to_string_lossy().as_ref())
                        .map_or(false, |entry| entry.kind == EntryKind::Directory)
                {
                    parent = parent
                        .parent()
                        .filter(|value| !value.as_os_str().is_empty())
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from("."));
                }
                grants.push(WriteGrant::DirectoryTree(parent));
            }
        }
    }
    let policy = ExecutionPolicy::new(grants).normalize()?;
    if !policy.is_subset_of(ceiling)? {
        return Err(AutoCageError::new(
            ErrorKind::Policy,
            "changed-path policy exceeded its authorized ceiling",
        ));
    }
    Ok(policy)
}

/// Calculate a transparent, deterministic exposure proxy over the immutable
/// source manifest. Each covered regular file costs 1, or 10 under a fixed
/// high-impact path heuristic. A recursive directory grant additionally costs
/// 10 for each existing writable directory entry it exposes. These are policy
/// weights, not exploit probabilities. Raw counts are reported separately.
pub fn measure_cost(policy: &ExecutionPolicy, manifest: &[ManifestEntry]) -> PolicyCost {
    let files = manifest
        .iter()
        .filter(|entry| {
            entry.kind == EntryKind::RegularFile
                && policy.write_grants.iter().any(|grant| match grant {
                    WriteGrant::FileContents(path) => Path::new(&entry.path) == path,
                    WriteGrant::DirectoryTree(path) => {
                        path_is_same_or_child(Path::new(&entry.path), path)
                    }
                })
        })
        .collect::<Vec<_>>();
    let directories = manifest
        .iter()
        .filter(|entry| {
            entry.kind == EntryKind::Directory
                && policy.write_grants.iter().any(|grant| match grant {
                    WriteGrant::FileContents(_) => false,
                    WriteGrant::DirectoryTree(path) => {
                        path_is_same_or_child(Path::new(&entry.path), path)
                    }
                })
        })
        .collect::<Vec<_>>();
    let file_weight_total = files
        .iter()
        .map(|entry| if high_impact_path(&entry.path) { 10 } else { 1 })
        .sum::<u64>();
    let root_directory_writable = policy
        .write_grants
        .iter()
        .any(|grant| matches!(grant, WriteGrant::DirectoryTree(path) if path == Path::new(".")));
    let writable_directories = directories.len() + if root_directory_writable { 1 } else { 0 };
    let directory_entry_weight_total = writable_directories as u64 * DIRECTORY_ENTRY_WEIGHT;
    PolicyCost {
        schema: COST_SCHEMA,
        weighted_writable_exposure: file_weight_total + directory_entry_weight_total,
        writable_regular_files: files.len(),
        writable_directories,
        recursive_directory_grants: policy
            .write_grants
            .iter()
            .filter(|grant| matches!(grant, WriteGrant::DirectoryTree(_)))
            .count(),
        permission_rules: policy.write_grants.len(),
        file_weight_total,
        directory_entry_weight_total,
    }
}

fn high_impact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".github/workflows/",
        "deploy/",
        "deployment/",
        "infra/",
        "scripts/",
        "package.json",
        "pyproject.toml",
        "cargo.toml",
    ]
    .iter()
    .any(|prefix| lower == *prefix || lower.starts_with(prefix))
}

/// Candidate children for one recursive grant. Files retain content-only
/// authority; existing directories remain recursive grants. If the task needs
/// the current directory's own entry operations, verifier replay rejects this
/// split and the parent grant remains the best known candidate.
pub fn split_directory(grant_path: &Path, manifest: &[ManifestEntry]) -> Vec<WriteGrant> {
    let mut children = Vec::new();
    for entry in manifest {
        let path = Path::new(&entry.path);
        let is_direct_child = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or(grant_path == Path::new("."), |parent| parent == grant_path);
        if !is_direct_child {
            continue;
        }
        match entry.kind {
            EntryKind::Directory => children.push(WriteGrant::DirectoryTree(path.to_path_buf())),
            EntryKind::RegularFile => children.push(WriteGrant::FileContents(path.to_path_buf())),
            EntryKind::Symlink | EntryKind::Special => {}
        }
    }
    children.sort();
    children
}

/// Run bounded policy search. `max_replays` includes the three final fresh
/// validation runs; candidates are never promoted with fewer than three.
pub fn optimize<F>(
    ceiling: &ExecutionPolicy,
    seed: &ExecutionPolicy,
    manifest: &[ManifestEntry],
    strategy: SearchStrategy,
    max_replays: usize,
    mut validate: F,
) -> Result<OptimizationResult>
where
    F: FnMut(&ExecutionPolicy) -> Result<TrialObservation>,
{
    if !(4..=100).contains(&max_replays) {
        return Err(AutoCageError::new(
            ErrorKind::Policy,
            "optimizer replay budget must be between 4 and 100, including three final validations",
        ));
    }
    ceiling.validate_global_invariants()?;
    let ceiling = ceiling.normalize()?;
    let seed = seed.normalize()?;
    if !seed.is_subset_of(&ceiling)? {
        return Err(AutoCageError::new(
            ErrorKind::Policy,
            "optimizer seed exceeds authorized ceiling",
        ));
    }
    let started = Instant::now();
    let ceiling_cost = measure_cost(&ceiling, manifest);
    let mut current = ceiling.clone(); // broad baseline is known to have passed
    let mut trials = Vec::new();
    let mut rejected = 0;
    let reserve = if max_replays >= 3 { 3 } else { max_replays };
    let search_budget = max_replays.saturating_sub(reserve);

    if seed != ceiling && trials.len() < search_budget {
        let passed = run_trial(&seed, manifest, &mut validate, &mut trials)?;
        if passed {
            current = seed;
        } else {
            rejected += 1;
        }
    }

    // Greedy and random baselines receive the same first-level, repository-
    // derived atomization when final-delta inference misses transient writes.
    // Their distinction from F is how they test removals after this shared
    // candidate vocabulary, not whether they receive useful initial atoms.
    if current == ceiling
        && strategy != SearchStrategy::Hierarchical
        && trials.len() < search_budget
    {
        let children = split_directory(Path::new("."), manifest);
        let decomposition = ExecutionPolicy::new(children).normalize()?;
        if decomposition != ceiling && decomposition.is_subset_of(&ceiling)? {
            if run_trial(&decomposition, manifest, &mut validate, &mut trials)? {
                current = decomposition;
            } else {
                rejected += 1;
            }
        }
    }

    match strategy {
        SearchStrategy::Hierarchical => {
            let mut seen = BTreeSet::new();
            loop {
                // Spend replay budget on the split with the largest estimated
                // exposure reduction first. A plain lexical walk wastes the
                // budget expanding small branches before large subtrees.
                let mut split_candidates = current
                    .write_grants
                    .iter()
                    .filter_map(|grant| {
                        let WriteGrant::DirectoryTree(path) = grant else {
                            return None;
                        };
                        let key = path.to_string_lossy().into_owned();
                        if seen.contains(&key) {
                            return None;
                        }
                        let children = split_directory(path, manifest);
                        if children.is_empty() {
                            return None;
                        }
                        let parent_cost =
                            measure_cost(&ExecutionPolicy::new(vec![grant.clone()]), manifest)
                                .weighted_writable_exposure;
                        // Estimate a branch's full narrowing opportunity by
                        // its content-only leaf grants. This is an ordering
                        // heuristic, not a proposed or authorized policy;
                        // replay validation still decides whether directory
                        // entry authority is required.
                        let leaf_files = manifest
                            .iter()
                            .filter(|entry| {
                                entry.kind == EntryKind::RegularFile
                                    && path_is_same_or_child(Path::new(&entry.path), path)
                            })
                            .map(|entry| WriteGrant::FileContents(PathBuf::from(&entry.path)))
                            .collect::<Vec<_>>();
                        let leaf_cost = measure_cost(&ExecutionPolicy::new(leaf_files), manifest)
                            .weighted_writable_exposure;
                        Some((
                            parent_cost.saturating_sub(leaf_cost),
                            key,
                            grant.clone(),
                            children,
                        ))
                    })
                    .collect::<Vec<_>>();
                split_candidates
                    .sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
                let candidate_split = split_candidates.into_iter().next();
                let Some((_, key, parent, children)) = candidate_split else {
                    break;
                };
                seen.insert(key.clone());
                if trials.len() >= search_budget {
                    break;
                }
                let mut grants = current
                    .write_grants
                    .iter()
                    .filter(|grant| **grant != parent)
                    .cloned()
                    .collect::<Vec<_>>();
                grants.extend(children);
                let proposal = ExecutionPolicy::new(grants).normalize()?;
                if !proposal.is_subset_of(&ceiling)? {
                    continue;
                }
                if proposal == current {
                    continue;
                }
                if run_trial(&proposal, manifest, &mut validate, &mut trials)? {
                    current = proposal;
                    // First expose top-level structure, then narrow one
                    // highest-value subtree before spending the remaining
                    // budget on sibling-group removal and validation.
                    if key != "." {
                        break;
                    }
                } else {
                    rejected += 1;
                }
            }
            prune_recursive_grants(
                &mut current,
                manifest,
                &ceiling,
                search_budget,
                &mut trials,
                &mut rejected,
                &mut validate,
            )?;
            // Remove exact-file grants in sibling groups. Failed groups are
            // bisected deterministically; successful removals are retained.
            let groups = current
                .write_grants
                .iter()
                .filter_map(|grant| match grant {
                    WriteGrant::FileContents(path) => Some((parent_key(path), grant.clone())),
                    _ => None,
                })
                .fold(
                    BTreeMap::<String, Vec<WriteGrant>>::new(),
                    |mut all, (key, grant)| {
                        all.entry(key).or_default().push(grant);
                        all
                    },
                );
            let mut remover = GroupRemover {
                manifest,
                ceiling: &ceiling,
                budget: search_budget,
                trials: &mut trials,
                rejected: &mut rejected,
                validate: &mut validate,
            };
            for group in groups.into_values() {
                remover.remove(&mut current, group)?;
            }
        }
        SearchStrategy::Greedy | SearchStrategy::Random(_) => {
            let mut atoms = current.write_grants.clone();
            if let SearchStrategy::Random(seed) = strategy {
                deterministic_shuffle(&mut atoms, seed);
            }
            for atom in atoms {
                if trials.len() >= search_budget {
                    break;
                }
                let proposal = ExecutionPolicy::new(
                    current
                        .write_grants
                        .iter()
                        .filter(|grant| **grant != atom)
                        .cloned()
                        .collect(),
                )
                .normalize()?;
                if run_trial(&proposal, manifest, &mut validate, &mut trials)? {
                    current = proposal;
                } else {
                    rejected += 1;
                }
            }
        }
    }

    let search_replays = trials.len();
    let mut validation_replays = 0;
    let mut validation_passed = current == ceiling;
    if current != ceiling && max_replays.saturating_sub(trials.len()) >= 3 {
        validation_passed = true;
        for _ in 0..3 {
            let passed = run_trial(&current, manifest, &mut validate, &mut trials)?;
            validation_replays += 1;
            if !passed {
                validation_passed = false;
                rejected += 1;
                break;
            }
        }
    }
    let status = if current == ceiling && rejected > 0 {
        "inconclusive"
    } else if current == ceiling {
        "no_narrower_candidate"
    } else if validation_passed {
        "validated"
    } else {
        "inconclusive"
    };
    let best_policy = if validation_passed {
        current
    } else {
        ceiling.clone()
    };
    let best_cost = measure_cost(&best_policy, manifest);
    Ok(OptimizationResult {
        strategy: strategy_name(strategy).to_owned(),
        status: status.to_owned(),
        authorized_ceiling: ceiling.clone(),
        best_policy,
        ceiling_cost,
        best_cost,
        search_replays,
        validation_replays,
        total_replays: trials.len(),
        optimization_elapsed_millis: started.elapsed().as_millis(),
        trials,
        rejected_trials: rejected,
    })
}

fn run_trial<F>(
    policy: &ExecutionPolicy,
    manifest: &[ManifestEntry],
    validate: &mut F,
    records: &mut Vec<TrialRecord>,
) -> Result<bool>
where
    F: FnMut(&ExecutionPolicy) -> Result<TrialObservation>,
{
    let observation = validate(policy)?;
    let required_checks = observation
        .security_checks
        .iter()
        .filter(|check| check.required_for_policy_promotion)
        .collect::<Vec<_>>();
    let checks_passed = !required_checks.is_empty()
        && required_checks
            .iter()
            .all(|check| check.status == SecurityCheckStatus::Passed);
    let security_canaries_passed = observation.security_canaries_passed && checks_passed;
    let passed = observation.verifier_passed && security_canaries_passed;
    records.push(TrialRecord {
        policy: policy.clone(),
        cost: measure_cost(policy, manifest),
        passed,
        security_canaries_passed,
        security_checks: observation.security_checks,
        elapsed_millis: observation.elapsed_millis,
        classification: observation.classification,
    });
    Ok(passed)
}

struct GroupRemover<'a, F> {
    manifest: &'a [ManifestEntry],
    ceiling: &'a ExecutionPolicy,
    budget: usize,
    trials: &'a mut Vec<TrialRecord>,
    rejected: &'a mut usize,
    validate: &'a mut F,
}

fn prune_recursive_grants<F>(
    current: &mut ExecutionPolicy,
    manifest: &[ManifestEntry],
    ceiling: &ExecutionPolicy,
    budget: usize,
    trials: &mut Vec<TrialRecord>,
    rejected: &mut usize,
    validate: &mut F,
) -> Result<()>
where
    F: FnMut(&ExecutionPolicy) -> Result<TrialObservation>,
{
    let mut groups = current
        .write_grants
        .iter()
        .filter_map(|grant| match grant {
            WriteGrant::DirectoryTree(path) => Some((parent_key(path), grant.clone())),
            WriteGrant::FileContents(_) => None,
        })
        .fold(
            BTreeMap::<String, Vec<WriteGrant>>::new(),
            |mut all, (key, grant)| {
                all.entry(key).or_default().push(grant);
                all
            },
        )
        .into_iter()
        .map(|(key, group)| {
            let exposure = group
                .iter()
                .map(|grant| {
                    measure_cost(&ExecutionPolicy::new(vec![grant.clone()]), manifest)
                        .weighted_writable_exposure
                })
                .sum::<u64>();
            (key, group, exposure)
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    let mut remover = GroupRemover {
        manifest,
        ceiling,
        budget,
        trials,
        rejected,
        validate,
    };
    for (_, group, _) in groups {
        remover.remove(current, group)?;
    }
    Ok(())
}

impl<F> GroupRemover<'_, F>
where
    F: FnMut(&ExecutionPolicy) -> Result<TrialObservation>,
{
    fn remove(&mut self, current: &mut ExecutionPolicy, group: Vec<WriteGrant>) -> Result<()> {
        if group.is_empty() || self.trials.len() >= self.budget {
            return Ok(());
        }
        let group_set = group.iter().collect::<BTreeSet<_>>();
        let proposal = ExecutionPolicy::new(
            current
                .write_grants
                .iter()
                .filter(|grant| !group_set.contains(grant))
                .cloned()
                .collect(),
        )
        .normalize()?;
        if proposal.is_subset_of(self.ceiling)? && proposal != *current {
            if run_trial(&proposal, self.manifest, self.validate, self.trials)? {
                *current = proposal;
                return Ok(());
            }
            *self.rejected += 1;
        }
        if group.len() > 1 && self.trials.len() < self.budget {
            let middle = group.len() / 2;
            self.remove(current, group[..middle].to_vec())?;
            self.remove(current, group[middle..].to_vec())?;
        }
        Ok(())
    }
}

fn parent_key(path: &Path) -> String {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_owned())
}

fn deterministic_shuffle<T>(items: &mut [T], mut state: u64) {
    // Published xorshift64* stream; fixed seed makes trial ordering reproducible.
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    for index in (1..items.len()).rev() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let random = state.wrapping_mul(0x2545f4914f6cdd1d);
        items.swap(index, (random as usize) % (index + 1));
    }
}

fn strategy_name(strategy: SearchStrategy) -> &'static str {
    match strategy {
        SearchStrategy::Hierarchical => "hierarchical",
        SearchStrategy::Greedy => "greedy",
        SearchStrategy::Random(_) => "random",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(paths: &[(&str, EntryKind)]) -> Vec<ManifestEntry> {
        paths
            .iter()
            .map(|(path, kind)| ManifestEntry {
                path: (*path).into(),
                kind: kind.clone(),
                mode: 0o644,
                size: 1,
                sha256: Some("x".into()),
            })
            .collect()
    }
    fn pass() -> TrialObservation {
        TrialObservation {
            verifier_passed: true,
            security_canaries_passed: true,
            security_checks: vec![SecurityCheckRecord {
                name: "synthetic_required_check".into(),
                status: SecurityCheckStatus::Passed,
                required_for_policy_promotion: true,
                evidence: "executed test control".into(),
            }],
            elapsed_millis: 1,
            classification: "pass".into(),
        }
    }

    #[test]
    fn changed_policy_distinguishes_contents_from_directory_entries() {
        let before = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
            ("tests", EntryKind::Directory),
        ]);
        let after = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
            ("src/new.rs", EntryKind::RegularFile),
            ("tests", EntryKind::Directory),
        ]);
        let policy = derive_changed_policy(&before, &after, &ExecutionPolicy::baseline()).unwrap();
        assert_eq!(
            policy.write_grants,
            vec![WriteGrant::DirectoryTree(PathBuf::from("src"))]
        );
    }

    #[test]
    fn directory_grant_costs_more_than_exact_file_even_with_one_rule() {
        let tree = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
            ("src/b.rs", EntryKind::RegularFile),
        ]);
        let exact = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        let broad = ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from("src"))]);
        assert_eq!(measure_cost(&exact, &tree).weighted_writable_exposure, 1);
        assert_eq!(measure_cost(&broad, &tree).weighted_writable_exposure, 12);
        assert_eq!(
            measure_cost(&ExecutionPolicy::baseline(), &tree).writable_directories,
            2
        );
    }

    #[test]
    fn optimizer_never_accepts_failed_security_canary_and_counts_validation() {
        let tree = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
        ]);
        let ceiling = ExecutionPolicy::baseline();
        let seed = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        let result = optimize(
            &ceiling,
            &seed,
            &tree,
            SearchStrategy::Hierarchical,
            8,
            |_| {
                Ok(TrialObservation {
                    security_canaries_passed: false,
                    ..pass()
                })
            },
        )
        .unwrap();
        assert_eq!(result.best_policy, ceiling);
        assert_ne!(result.status, "validated");
        assert!(result.trials.iter().all(|trial| !trial.passed));
    }

    #[test]
    fn untested_required_security_check_cannot_promote_a_policy() {
        let tree = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
        ]);
        let ceiling = ExecutionPolicy::baseline();
        let seed = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        let result = optimize(&ceiling, &seed, &tree, SearchStrategy::Greedy, 4, |_| {
            let mut observation = pass();
            observation.security_checks[0].status = SecurityCheckStatus::NotTested;
            Ok(observation)
        })
        .unwrap();
        assert_ne!(result.status, "validated");
        assert!(result.trials.iter().all(|trial| !trial.passed));
        assert!(result
            .trials
            .iter()
            .all(|trial| { trial.security_checks[0].status == SecurityCheckStatus::NotTested }));
    }

    #[test]
    fn optimizer_runs_three_fresh_validation_trials_before_promotion() {
        let tree = manifest(&[
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
        ]);
        let ceiling = ExecutionPolicy::baseline();
        let seed = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        let result = optimize(
            &ceiling,
            &seed,
            &tree,
            SearchStrategy::Hierarchical,
            4,
            |_| Ok(pass()),
        )
        .unwrap();
        assert_eq!(result.status, "validated");
        assert_eq!(result.validation_replays, 3);
        assert_eq!(result.total_replays, 4);
        assert_eq!(result.best_policy, seed);
    }

    #[test]
    fn fixed_and_random_removal_share_manifest_fallback_for_transient_writes() {
        let tree = manifest(&[
            ("build", EntryKind::Directory),
            ("build/seed", EntryKind::RegularFile),
            ("src", EntryKind::Directory),
            ("src/a.rs", EntryKind::RegularFile),
        ]);
        let ceiling = ExecutionPolicy::baseline();
        let seed = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        for strategy in [SearchStrategy::Greedy, SearchStrategy::Random(0x1234)] {
            let result = optimize(&ceiling, &seed, &tree, strategy, 8, |policy| {
                let has_build = policy
                    .write_grants
                    .contains(&WriteGrant::DirectoryTree(PathBuf::from("build")));
                let has_src = policy
                    .write_grants
                    .contains(&WriteGrant::DirectoryTree(PathBuf::from("src")));
                Ok(TrialObservation {
                    verifier_passed: has_build && has_src,
                    ..pass()
                })
            })
            .unwrap();
            assert_eq!(result.status, "validated");
            assert!(result
                .best_policy
                .write_grants
                .contains(&WriteGrant::DirectoryTree(PathBuf::from("build"))));
            assert!(result.total_replays <= 8);
        }
    }

    #[test]
    fn empty_candidate_is_validated_for_read_only_tasks() {
        let tree = manifest(&[("README.md", EntryKind::RegularFile)]);
        let ceiling = ExecutionPolicy::baseline();
        let seed = ExecutionPolicy::new(vec![]);
        let result = optimize(
            &ceiling,
            &seed,
            &tree,
            SearchStrategy::Hierarchical,
            4,
            |_| Ok(pass()),
        )
        .unwrap();
        assert_eq!(result.best_policy.write_grants.len(), 0);
    }

    #[test]
    fn high_impact_file_weight_is_separate_from_raw_count() {
        let tree = manifest(&[
            (".github", EntryKind::Directory),
            (".github/workflows", EntryKind::Directory),
            (".github/workflows/ci.yml", EntryKind::RegularFile),
        ]);
        let policy = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from(
            ".github/workflows/ci.yml",
        ))]);
        let cost = measure_cost(&policy, &tree);
        assert_eq!(cost.writable_regular_files, 1);
        assert_eq!(cost.weighted_writable_exposure, 10);
    }

    #[test]
    fn m35_controlled_search_scaling_matrix() {
        let mut rows = Vec::new();
        for atom_count in [4_usize, 8, 16, 32, 64] {
            for layout in ["clustered", "dispersed"] {
                let mut tree = Vec::new();
                let mut required = Vec::new();
                for index in 0..atom_count {
                    let directory = format!("atom{index:02}");
                    let file = format!("{directory}/payload.txt");
                    tree.push(ManifestEntry {
                        path: directory,
                        kind: EntryKind::Directory,
                        mode: 0o755,
                        size: 0,
                        sha256: None,
                    });
                    tree.push(ManifestEntry {
                        path: file.clone(),
                        kind: EntryKind::RegularFile,
                        mode: 0o644,
                        size: 1,
                        sha256: Some("synthetic".to_owned()),
                    });
                    let is_required = match layout {
                        "clustered" => index < atom_count / 4,
                        _ => index % 4 == 0,
                    };
                    if is_required {
                        required.push(PathBuf::from(file));
                    }
                }
                let ceiling = ExecutionPolicy::baseline();
                for (strategy_name, strategy) in [
                    ("greedy", SearchStrategy::Greedy),
                    ("random", SearchStrategy::Random(0x4155_544f_4341_4745)),
                    ("hierarchical", SearchStrategy::Hierarchical),
                ] {
                    let result = optimize(&ceiling, &ceiling, &tree, strategy, 100, |policy| {
                        let passed = required.iter().all(|path| {
                            policy.write_grants.iter().any(|grant| match grant {
                                WriteGrant::FileContents(file) => file == path,
                                WriteGrant::DirectoryTree(directory) => {
                                    path_is_same_or_child(path, directory)
                                }
                            })
                        });
                        Ok(TrialObservation {
                            verifier_passed: passed,
                            ..pass()
                        })
                    })
                    .unwrap();
                    let ceiling_cost = result.ceiling_cost.weighted_writable_exposure;
                    rows.push(serde_json::json!({
                        "atom_count": atom_count,
                        "layout": layout,
                        "required_atom_count": required.len(),
                        "strategy": strategy_name,
                        "status": result.status,
                        "utility_validated": result.status == "validated",
                        "search_replays": result.search_replays,
                        "validation_replays": result.validation_replays,
                        "total_replays": result.total_replays,
                        "ceiling_weighted_exposure": ceiling_cost,
                        "best_weighted_exposure": result.best_cost.weighted_writable_exposure,
                        "reduction_percent": if ceiling_cost == 0 { 0.0 } else { (ceiling_cost - result.best_cost.weighted_writable_exposure) as f64 * 100.0 / ceiling_cost as f64 },
                        "grants": result.best_policy.write_grants,
                    }));
                }
            }
        }
        if let Ok(path) = std::env::var("AUTOCAGE_M35_SCALING_OUTPUT") {
            std::fs::write(path, serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
        }
        for row in &rows {
            println!("M35_SCALE_JSON:{row}");
        }
        assert_eq!(rows.len(), 30);
    }
}
