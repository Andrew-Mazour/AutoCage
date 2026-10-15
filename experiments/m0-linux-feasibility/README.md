# M0 Linux feasibility harness

This is disposable validation code for the proposed Linux enforcement boundary. It is not AutoCage runtime code. A trusted Python controller runs outside Bubblewrap, creates synthetic fixtures, runs bounded probes, and checks filesystem/network outcomes from outside the sandbox. It uses only the Python standard library; the guest needs Bubblewrap, pytest, and the official Ubuntu AppArmor packages/profile described below. The same setup script installs Rust/Cargo, rustfmt, and diffutils for the M1 runner.

The harness is intentionally strict: it runs only as an unprivileged user on Ubuntu 24.04 ARM64 with Linux 6.8 or later. Namespace and mount setup use required Bubblewrap flags. Setup failure is a failure; there is no unsandboxed retry. Exit codes are `0` for PASS, `1` for FAIL, and `2` for BLOCKED.

## Isolated Lima guest on Apple Silicon

The Lima VM has no host directory mounts. Copy only this synthetic experiment directory into the guest after provisioning. The setup script passes `--containerd=none` so Lima does not provision an unrelated container runtime.

1. On macOS, install Lima if needed:

   ```sh
   brew install lima
   ```

2. Create and boot the named ARM64 Ubuntu 24.04 guest:

   ```sh
   bash experiments/m0-linux-feasibility/setup/create-lima-vm.sh
   ```

   The script uses Apple Virtualization (`vz`) and `--mount-none`. Before proceeding, inspect `~/.lima/autocage-m0/lima.yaml` and verify `mounts: null` (Lima's empty mount list); do not add host mounts.

3. Install test packages and configure AppArmor inside that guest only. Run as the ordinary Lima user (the script uses `sudo` only for package/profile administration):

   ```sh
   limactl copy experiments/m0-linux-feasibility/setup/install-guest-deps.sh autocage-m0:/tmp/install-guest-deps.sh
   limactl shell autocage-m0 -- bash /tmp/install-guest-deps.sh
   ```

   The script first checks for an already loaded Bubblewrap profile and refuses to replace or stack an unreviewed one. It requires AppArmor's global unprivileged-userns restriction to equal `1`, installs Ubuntu's `apparmor-profiles` and `apparmor-utils` plus test/build tools, then loads only the packaged `/usr/share/apparmor/extra-profiles/bwrap-userns-restrict`. It verifies the `bwrap` and `unpriv_bwrap` profiles are enforced and runs an unprivileged namespace/profile/capability smoke probe. It does not set Bubblewrap setuid, change the global sysctl, or use `--share-net`.

   The official profile is attached to `/usr/bin/bwrap`; its setup profile permits namespace setup and its stacked child profile denies capabilities. The latter also permits broad operations within the sandbox process, so M0's tested Bubblewrap mount plan and mandatory namespaces remain essential. The child must run with `--disable-userns --assert-userns-disabled`.

4. Transfer only the harness and run it inside Linux:

   ```sh
   limactl copy --backend=scp --recursive experiments/m0-linux-feasibility autocage-m0:/tmp/
   limactl shell autocage-m0 -- python3 /tmp/m0-linux-feasibility/scripts/run_m0.py --output /tmp/m0-result.json
   ```

5. Copy the JSON evidence back into the repository:

   ```sh
   limactl copy autocage-m0:/tmp/m0-result.json experiments/m0-linux-feasibility/results/
   ```

The harness uses `/tmp/autocage-m0-*` only inside the guest and deletes its synthetic lab after a normal run. Add `--keep-lab` to retain it for diagnosis. It never reads or records host environment values, uses only a synthetic environment canary, and contacts no external service. The only network probes are a local synthetic listener and the reserved TEST-NET-1 address.

## M1 runner tests

After the guest setup, copy only `Cargo.toml`, `Cargo.lock`, `src/`, and `tests/` into the VM and run the commands in the [M1 report](../m1-runner/REPORT.md). That report records the exact environment, 22 unit tests, 6 Linux integration tests, release build, tested boundary, and explicit untested cases.

## Coverage

- Host distribution, architecture, kernel, Bubblewrap version, and unprivileged execution preflight.
- Individual and combined user, mount, PID, IPC, UTS, and network namespace probes.
- `--disable-userns --assert-userns-disabled` nested-user-namespace probe, with a no-flag control; UID/GID maps and all five capability sets are recorded, and the expected enforced AppArmor child profile is checked.
- Read-only workspace base with an exact-file writable bind, writable directory bind, and nested read-only file over writable directory.
- Existing-file writes, sibling denials, file creation, unlink/rename/atomic replacement, symlink chains, parent traversal, hard links, tmpfs, and original/host canaries.
- Environment clearing, inherited-FD positive/leak controls and `close_fds` mitigation, Unix socket, child-process network inheritance, timeout and process-group cleanup.
- Python + pytest with `/usr` and minimal devices/proc/tmp mounts, both with and without a read-only `/etc` mount.

For each result, distinguish PASS (executed and passed), FAIL (executed and failed), BLOCKED (a prerequisite prevented the test), and NOT TESTED. A blocked prerequisite is never an implicit pass. The JSON includes the exact Bubblewrap argv, captured command output, runtime facts, package versions, official profile hash, individual results, and limitations. The current passing result is [`m0-20261011-ubuntu-24.04-arm64.json`](results/m0-20261011-ubuntu-24.04-arm64.json); see the [report](results/REPORT.md). The result is a bounded canary, not a sandbox-escape proof or availability-isolation claim.
