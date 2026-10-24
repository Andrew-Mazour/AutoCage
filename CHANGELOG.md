# Changelog

## 0.1.0-rc.1 — 2026-10-19

First release candidate for review; not published. AutoCage-owned code and documentation are licensed Apache-2.0.

- Rust runner with Bubblewrap namespace and filesystem enforcement on the validated Ubuntu ARM64 configuration.
- Inspect AI task/solver/scorer integration, pinned to 0.3.281.
- No-cost synthetic clean/adversarial regression suite with independent task verification, canary checks, selected syscall observations, and sealed run identity.
- Optional local Aider/Ollama example; no hosted inference requirement.
- Historical optimization and profile experiments retained as research evidence.

Known limits include one validated Linux distribution/architecture, incomplete syscall observation, no aggregate CPU/memory/process isolation, no hosted-agent bridge, and no general claim of model resistance or sandbox-escape prevention. Third-party runtime dependencies and optional model weights are not bundled and retain their own licenses.

## M6.1 release preparation — 2026-10-23

- Applied Apache-2.0 to AutoCage-owned code and documentation; synchronized Rust and Python package metadata.
- Verified the Python adapter wheel includes its license file.
- Excluded raw per-sample Inspect workspaces, logs, traces, and real-agent run artifacts from source control.
- Repeated the local Ubuntu ARM64, M0, M4, Rust, Python, and no-cost Inspect release checks from a clean guest source copy.
- No GitHub push or hosted workflow result is claimed; repository authentication remains unavailable.

## M6.2 publication — 2026-10-24

- Committed and pushed the release candidate to `main` without rewriting prior history.
- Both portable GitHub Actions validation and Ubuntu 24.04 ARM64 enforcement/Inspect regression workflows passed.
- Published the `0.1.0-rc.1` prerelease after checking the local Lima and hosted enforcement gates.
- Retained pre-1.0 scope and documented the supported platform, selected syscall evidence, and security limitations.
