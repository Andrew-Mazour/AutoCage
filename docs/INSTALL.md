# Installation and reproducible checks

AutoCage's enforcement backend is supported only on the validated Linux configuration: **Ubuntu 24.04 ARM64, Linux 6.8 or later, Bubblewrap 0.9 or later, and Ubuntu's official `bwrap-userns-restrict` AppArmor profile loaded in enforce mode**. Python 3.12 and Rust/Cargo 1.75 were used for the release-candidate validation. Other platforms and distributions may work, but are not validated.

AutoCage does not sandbox processes natively on macOS or Windows. On an ARM64 Mac, use the isolated Lima VM below. Keep the VM's Lima configuration at `mounts: null`; do not share the host home directory, SSH agent, sockets, credentials, or project directory. Clone the public repository inside the guest after setup.

## Ubuntu setup

Run `experiments/m0-linux-feasibility/setup/install-guest-deps.sh` as an ordinary user in a disposable Ubuntu 24.04 ARM64 guest. It checks the global AppArmor user-namespace restriction, refuses a pre-existing Bubblewrap profile, installs distribution packages, loads only Ubuntu's packaged profile, and performs an unprivileged namespace smoke test. It does not disable AppArmor, set Bubblewrap setuid, or relax the required namespaces.

The setup requires `sudo` for package installation and loading the official profile inside the guest. If a Bubblewrap profile is already loaded, the script stops; inspect the existing profile before changing anything. Do not work around setup failures by disabling AppArmor or using Bubblewrap's shared-network option.

Then clone/build and install the pinned Inspect adapter:

```sh
git clone https://github.com/Andrew-Mazour/AutoCage.git
cd AutoCage
cargo build --locked --release
cargo install --path . --locked
export PATH="$HOME/.cargo/bin:$PATH"
autocage check
python3 -m venv .venv-inspect
source .venv-inspect/bin/activate
python -m pip install -r integrations/inspect_autocage/requirements.lock
python -m pip install -e integrations/inspect_autocage --no-deps
scripts/run-inspect-quickstart.sh
```

The pinned Python environment installs Inspect AI `0.3.281`. The adapter is built from the checkout and is not published as a separate package. No model, API key, cloud account, or paid service is needed for the quickstart.

`cargo install` installs only into the Linux guest user's Cargo bin directory; it does not install a system service. The quickstart script deliberately uses the freshly built `target/release/autocage` unless `AUTOCAGE_BINARY` is set.

## macOS with isolated Lima

From the repository root on an Apple Silicon Mac:

```sh
brew install lima
bash experiments/m0-linux-feasibility/setup/create-lima-vm.sh
limactl copy experiments/m0-linux-feasibility/setup/install-guest-deps.sh autocage-m0:/tmp/install-guest-deps.sh
limactl shell autocage-m0 -- bash /tmp/install-guest-deps.sh
```

Inspect `~/.lima/autocage-m0/lima.yaml` and confirm `mounts: null`. The script uses Apple Virtualization and does not configure host directory sharing. Then clone AutoCage inside the VM and follow the Ubuntu commands. The guest needs network access for initial package and source downloads; the AutoCage workload itself remains in a private no-egress network namespace.

## Prerequisite check and troubleshooting

After building the release binary, run:

```sh
scripts/check-linux-prerequisites.sh
```

It reports the distribution, architecture, kernel, Bubblewrap version, AppArmor restriction, and loaded profiles, then calls `autocage check`. Exit code `2` means the environment is unsupported or missing a required control. The script is diagnostic only and does not alter host or guest security settings.

Common setup failures:

- **Unsupported OS, architecture, or kernel:** use the validated Ubuntu 24.04 ARM64 guest with Linux 6.8+.
- **AppArmor restriction is not `1`:** stop. Do not disable the global restriction. Recreate/use a clean supported guest or investigate the OS configuration.
- **Bubblewrap profile already loaded:** setup intentionally refuses to replace or stack it. Inspect the loaded profile and package source before proceeding.
- **`bwrap` or child profile is not enforced:** M0 and `autocage check` fail closed. Do not retry without required namespaces or with shared networking.
- **Verifier or task command fails:** inspect the per-sample JSON, AutoCage record, and stderr in the selected results directory. `INCONCLUSIVE`, missing traces, and untested controls are not passes.
- **Permission denied while creating the VM:** check the Lima installation and available host disk; do not change macOS security settings or add host mounts.

## Remove the local setup

The Rust binary is built under the repository's ignored `target/` directory. If installed with Cargo, remove it from the guest user's Cargo bin directory with `cargo uninstall autocage`. Remove the project-local Python environment with `deactivate` (if active), then remove `.venv-inspect/` from the checkout. The example results and logs can be deleted from the selected results directory after you have kept anything you need.

The Lima guest is disposable and has no host directory mounts. To remove the entire guest, first copy out any wanted evidence, then run `limactl stop autocage-m0` and `limactl delete autocage-m0` on the Mac. Deleting the guest removes its installed packages, AppArmor profile, source checkout, and local model assets; it does not change the Mac's security settings.

## CI and release checks

`.github/workflows/ci.yml` runs formatting, strict Clippy, Rust unit tests and release builds on Ubuntu x86_64 and ARM64, plus Python tests, pinned dependency checks, and local documentation-link checks. This validates compilation and portable components; it does not claim sandbox enforcement on those workers.

`.github/workflows/linux-enforcement.yml` runs only on a trusted push to `main` or a manual dispatch. It targets the GitHub-hosted Ubuntu 24.04 ARM64 runner, installs and inspects Ubuntu's official AppArmor profile in its disposable VM, then runs the full M0, Rust/Linux, M4, and M5 gates. It fails visibly when a prerequisite is unsupported; it never reports a blocked enforcement run as passed. The workflow has not yet been observed on GitHub-hosted infrastructure. The currently measured enforcement evidence comes from the isolated Lima guest described in the M0 and M5 reports.

Run the complete supported-guest gate locally with the same commands shown in the workflow. Do not treat portable CI success as a substitute for M0 or Linux integration tests.

## Artifacts and reproducibility

The no-cost quickstart saves evidence under `/tmp/autocage-inspect-quickstart-*` by default, or under a new, not-yet-existing `AUTOCAGE_RESULTS_ROOT`. Each result contains Inspect logs, per-sample JSON, selected traces, run contracts/records, and review patches. Outputs may include file paths, command metadata, and task content; inspect and redact them before sharing. Model files, credentials, host VM disks, and local runtime caches are not part of the repository.

Historical experiment protocols and results are retained under `experiments/`. These include failed and inconclusive results and must not be rewritten to match later code. The default `.gitignore` excludes build output, Python environments/caches, and local AutoCage runtime data.

## Release and license

The code is versioned `0.1.0-rc.1`; no binary or Python package has been published. AutoCage-owned code and documentation use Apache-2.0. The Rust and Python package metadata declare `Apache-2.0`, and the Python adapter distribution includes its own copy of the license text. Runtime dependencies, upstream benchmark projects, and optional model weights are separate works governed by their own terms; none are bundled.
