# 0.1.0-rc.1 release checklist and validation record

**Release gate:** PASS for the supported Lima guest and GitHub-hosted workflows at `bde4272`. AutoCage-owned code and documentation are licensed Apache-2.0. The public prerelease state is available from the repository's GitHub Releases page.

## Prioritized checklist

1. Keep the public value proposition and M5 security claims consistent with measured evidence.
2. Provide one clean-checkout installation path and a quickstart that asserts its expected result, not just a successful process exit.
3. Separate portable build/unit checks from privileged OS enforcement checks; never treat missing controls as passing.
4. Verify a fresh source copy and fresh Python environment in the supported guest.
5. Inspect generated artifacts and historical evidence for credentials, host paths, and unnecessary binaries before staging or publishing.
6. Verify package licensing and prevent raw execution workspaces/transcripts from entering the source release.
7. Configure a valid Git author identity before committing and verify remote/CI status before publication.
8. Run the local release gate and record exact outputs and any unsupported external CI result.

## Current evidence

The M6.1 section below is a frozen historical snapshot. The M6.2 addendum records the later hosted workflow results without changing M6.1 evidence. See [installation and CI instructions](INSTALL.md) for exact commands and [M5's frozen results](../experiments/inspect-autocage-v1/results/2026-10-18/REPORT.md) for the original evaluation.

### Linux and Rust


- Clean source copy had no `.git`, build target, `.eval` archive, AppleDouble sidecar, or model weight.
- Environment: Ubuntu 24.04.5 ARM64; Linux 6.8.0-142-generic; Bubblewrap 0.9.0; strace 6.8; Rust/Cargo 1.75; Python 3.12.3.
- `cargo fmt --check`: PASS; strict locked Clippy: PASS; `cargo test --locked`: 47 unit + 22 live Linux integration tests PASS; locked release build: PASS; `autocage check`: PASS with `bwrap//&unpriv_bwrap (enforce)`.
- M0 harness: 41/41 PASS, no blocked, failed, or untested checks.
- M4 containment controller: 26/26 runs, verifiers, and selected traces collected; all 12 declared checks were true.
- `scripts/check-linux-prerequisites.sh`: PASS. Its initial draft tried to read a root-only AppArmor profile list as an ordinary user; it now delegates live profile verification to `autocage check` and does not require elevated read access.

### Python and Inspect


- Fresh Python 3.12 virtual environment installed the pinned `requirements.lock`; editable package installation used pinned setuptools 77.0.3 with PEP 639 metadata; `pip check`: PASS.
- Cargo package contents were explicitly allowlisted and inspected with `cargo package --list --allow-dirty --locked`: only the Rust CLI source/tests, manifests, README, and license are included; experiment data, Python integration assets, docs, traces, and generated caches are excluded.
- Inspect AI 0.3.281 and AutoCage adapter 0.1.0rc1 imported; 20 Inspect adapter tests, 4 quickstart assertion tests, and 5 M4 parser tests passed.
- Exact runtime dependency lock consistency: 82 exact package pins; setuptools is separately pinned as the Python build backend; documentation link check: 13 files PASS.
- Fresh CLI installation via `cargo install --locked --path . --root /tmp/autocage-m6-cargo-install` completed; the installed binary passed `autocage check` in the supported guest.
- The quickstart was run from the clean source copy. It scored 13/13 samples, with zero model calls. Broad and `src/` arms each passed 6/6 task verifiers; the read-only utility control failed as expected. All 13 AutoCage records/required controls validated. The `src/` arm observed 3 denials and 3 clean no-attempts with all canaries unchanged; the broad arm changed 3 adversarial canaries. The formatter found 3 adversarial security regressions and 3 clean comparisons with no observed difference.
- The first clean transfer attempted Python byte-compilation before filtering macOS AppleDouble metadata, then failed; the final clean copy excluded those sidecars. The quickstart's first omitted-venv invocation correctly rejected missing `inspect`; a later run exposed an assertion reading the normalized outcome rather than the explicit attempt category. Both issues were corrected and the quickstart passed with its documented environment and assertions.
- Compact, synthetic per-arm evidence: [M6 quickstart summary](../experiments/inspect-autocage-v1/results/2026-10-19-m6-quickstart/README.md). Raw traces and `.eval` archives remain in the isolated guest and are not redistributed.

### Licensing review

- The root `LICENSE` is the complete Apache License 2.0 text copied from the [Apache Software Foundation's official license page](https://www.apache.org/licenses/LICENSE-2.0.txt). The Python adapter carries an identical license file so its independently built wheel/sdist can include license text; Cargo and Python metadata both declare `Apache-2.0`.
- The owner authorized applying Apache-2.0 to AutoCage-owned code and documentation. The repository contains synthetic fixtures and evaluation code, not source trees copied from the pinned M3 benchmark repositories. No third-party model weights, research datasets, or upstream assets are bundled.
- Locked Rust crates declare MIT, Apache-2.0, or Unlicense-compatible terms. The pinned Python environment installs dependencies separately rather than vendoring them; their upstream notices remain governed by their own packages. This includes third-party MIT/BSD/Apache, PSF, MPL, and other permissive/weak-copyleft terms. [PyPI lists `zipfile-zstd` as MIT](https://pypi.org/project/zipfile-zstd/) despite its installed wheel metadata reporting `UNKNOWN`; the [Agent Client Protocol upstream repository](https://github.com/agentclientprotocol/agent-client-protocol) is Apache-2.0 despite its installed Python metadata omitting the field. Neither dependency's code is copied into AutoCage.
- No `NOTICE` file is added: AutoCage does not include upstream source or an existing third-party NOTICE-bearing work. This project is not an Apache Software Foundation project.
- No substantive licensing conflict was found for the source-only project distribution. This is a repository-level review, not a legal opinion; dependencies must retain their own licenses when separately installed or redistributed.

## M6.1 final validation (2026-10-23 UTC; historical snapshot)

The final rerun used a clean source copy in the existing isolated Lima guest, with no host directory mounts: Ubuntu 24.04.5 ARM64, Linux 6.8.0-142-generic, Bubblewrap 0.9.0, Rust/Cargo 1.75.0, Python 3.12.3, Inspect AI 0.3.281, and enforced `bwrap//&unpriv_bwrap` AppArmor profile.

- Rust: `cargo fmt --check`, strict locked Clippy, all 47 unit tests, all 22 live Linux integration tests, and `cargo build --locked --release`: PASS.
- Cargo distribution: `cargo package --locked --allow-dirty` built and verified a 21-file, 312.4 KiB source package; explicit root-anchored allowlist excludes experiments, integration sources, documentation, and generated artifacts.
- Runtime/M0: `autocage check` confirmed the enforced profile; M0 reported 41 PASS, 0 FAIL, 0 BLOCKED, and 0 NOT TESTED.
- M4: 26/26 executions, trusted verifiers, and selected traces collected across two replicates; all 12 declared checks passed.
- Python/Inspect: 20 adapter tests, 4 quickstart validator tests, 5 M4 parser tests, package-lock consistency, documentation links, and `pip check`: PASS. A built wheel included `dist-info/licenses/LICENSE` and declared `License-Expression: Apache-2.0`.
- No-cost quickstart: 13/13 Inspect samples scored, zero model calls; all 12 writable-arm task verifiers passed, and the read-only utility control failed as expected. All records and mandatory checks validated. The `src/` policy denied three adversarial writes and kept all six canaries unchanged; broad write allowed three and changed those canaries. Three adversarial comparisons were flagged as security regressions; clean comparisons had no observed difference.
- Compact machine-readable and human-readable evidence: [M6.1 final validation result](../experiments/inspect-autocage-v1/results/2026-10-23-m6-1-final-validation/README.md).
- The first transfer of this validation tree included one macOS AppleDouble sidecar and stopped at Python byte-compilation. The sidecar was removed from the disposable guest copy; the complete suite above passed on the clean copy. No host files or security settings were changed.
- M0/M4 JSON and Inspect run outputs were kept in the disposable guest under `/tmp`; no raw traces, transcripts, or per-sample staged workspaces were added to the source tree.

### GitHub Actions


Workflow definitions are in `.github/workflows/ci.yml` and `.github/workflows/linux-enforcement.yml`. Neither workflow has run on GitHub. The [official GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) lists `ubuntu-24.04-arm`; that label's availability does not validate the required user namespace, AppArmor profile, or Bubblewrap behavior. The configured enforcement workflow will attempt the official guest setup and fail instead of weakening controls. At M6.1, `gh auth status` reported the cached token invalid and a read-only `git ls-remote` could not authenticate; no fetch, push, or workflow dispatch occurred.

### Artifact review

Historical M0–M5 protocols and results are retained. Per-sample Inspect workspaces, raw traces, inspect logs, real-agent run records, and `.eval` archives are excluded by `.gitignore`; the compact synthetic summary remains available, and the raw runs can be regenerated. No model weights, VM disks, credentials, or build binaries are intended for source control. A targeted scan found no common GitHub/OpenAI/AWS token patterns, private-key headers, or host home path; this is not a general secret-detection guarantee.

## Release gate

The local technical release gate was **PASS** for the named Lima guest and documented scripted workload. At this historical point, the release remained unpublished, commits had not been pushed, and GitHub Actions had not run. The M6.2 addendum below records resolution of those blockers. The historical root commit retains its original machine-local author email; future release commits use the verified account email configured locally for this repository.

## M6.2 final publication validation (2026-10-24 UTC)

The release source is on `main` at commit `bde4272902c34b5c46b37715d55de8adf3b867a4`. The verified author identity for new commits is configured repository-locally as Andrew Mazour with the owner-provided, GitHub-verified primary address. The remote was fetched and confirmed to be an ancestor before pushing; no remote history was overwritten.

- GitHub Actions [portable validation](https://github.com/Andrew-Mazour/AutoCage/actions/runs/40137546025): **PASS** on Ubuntu x86_64 and ARM64.
- GitHub Actions [Linux enforcement and Inspect regression](https://github.com/Andrew-Mazour/AutoCage/actions/runs/40137546016): **PASS** on Ubuntu 24.04 ARM64. The job installed and loaded the official Ubuntu Bubblewrap AppArmor profile without disabling global restrictions, passed the namespace smoke test, ran all 47 unit tests and 22 live Linux integration tests, passed `autocage check`, completed all 41 M0 checks, and ran the M4 containment regression and 13-sample no-cost Inspect quickstart.
- Quickstart evidence: 13 samples, three intentionally detected broad-write regressions, and three clean comparisons. These are deterministic synthetic scenarios, not a model-resistance result.
- A previous run exposed a timing race in `interrupted_optimization_is_not_resumed_or_promoted`: recovery correctly refused to operate while an inherited sandbox lock remained held. The test now waits up to five seconds for lock release and still fails on any other recovery error. Production locking and sandbox policy were unchanged. The fixed test passed repeatedly in Lima and in the final hosted enforcement run.
- Final local verification in the supported Lima guest: formatting, strict Clippy, 47 unit tests, 22 Linux integration tests, and locked release build all passed.
- Release version: `0.1.0-rc.1`. The release remains pre-1.0 and does not claim production-grade sandbox security.
