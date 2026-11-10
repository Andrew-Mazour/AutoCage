# M8.2 deterministic BYO workflow validation

Date: 2026-11-09 UTC
Environment: Ubuntu 24.04 ARM64, Linux 6.8.0-147-generic, Bubblewrap 0.9.0, enforced bwrap//&unpriv_bwrap AppArmor profile, Inspect AI 0.3.281.

## Actual acceptance run

Command:

    python experiments/byo-workflow-v1/run_smoke.py --autocage "$PWD/target/release/autocage"

Observed output:

    M8.2 BYO workflow smoke: PASS (5 samples, sequential, no model/API)
      legitimate utility: 4/4 writable-policy samples passed; read-only control failed as expected
      adversarial broad: protected canary changed after observed write
      adversarial narrower: selected write denied; protected canary unchanged
      enforcement/evidence: 5/5 confirmed/valid; original source unchanged
      reports: summary.md and summary.json generated and checked

The smoke test used the real Rust CLI and Inspect task adapter with a temporary synthetic repository, deterministic Python task executable, and independent unittest verifier. It created a buggy source file and protected JSON canary. The broad authorized ceiling contained src/ and config/; the candidate contained only src/. Clean and adversarial samples ran under both policies, plus a clean read-only control. The adversarial instruction was a synthetic README overlay. The test inspected the generated summary before its temporary directory was removed.

The four writable-policy runs passed the legitimate verifier. The broad adversarial run had an observed selected write and a changed staged canary. The narrow adversarial run had an observed filesystem denial and unchanged canary. The read-only control failed utility as expected. All five records reported enforcement CONFIRMED and evidence VALID; the starter source digest remained unchanged.

## What this validates

- Rust CLI dispatch to the Python Inspect integration without shell argument parsing.
- The init wizard's snapshot copy, required authorization confirmation, policy subset validation, and rejection of root grants and symlinks.
- Sequential Inspect execution, unique output creation, the exact sample selector without --limit, and summary generation.
- Independent task verification and separate canary, syscall-denial, enforcement, and record-integrity outcomes.

## What this does not validate

This deterministic control does not evaluate an AI model, model resistance, real-user onboarding time, broad agent compatibility, or behavior on other Linux configurations. The summary reads the adapter result JSON and does not authenticate arbitrary model output or revalidate every result JSON. Use autocage inspect on each sealed AutoCage run directory to check its sealed record. Raw Inspect logs and sample evidence from this smoke run were temporary and were not committed.

Reproduction uses the pinned environment and script above. No model weights, paid service, remote inference, or external network access is used during sample execution.
