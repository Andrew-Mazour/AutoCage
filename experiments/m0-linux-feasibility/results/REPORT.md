# M0 Linux feasibility report

**Run:** 2026-10-11 UTC
**Verdict:** **PASS** — all mandatory M0 probes completed and passed in the disposable Ubuntu guest. This validates the tested mechanisms and launch discipline; it is not a general sandbox security proof.

## Environment and AppArmor remediation

- Host: ARM64 Mac, macOS 26.6.2; Homebrew 6.0.14; Lima 2.2.1.
- VM: Apple Virtualization (`vz`), ARM64, created with `--mount-none`; the generated Lima config had `mounts: null`. No host home, checkout, credentials, SSH/GitHub material, or sockets were shared.
- Guest: Ubuntu 24.04.5 LTS ARM64, Linux `6.8.0-142-generic`; ordinary user EUID 501, GID 1000.
- Bubblewrap: `0.9.0-1ubuntu0.3` (`bubblewrap 0.9.0`); Python 3.12.3; pytest 7.4.4.
- AppArmor: enabled (`Y`); `kernel.apparmor_restrict_unprivileged_userns=1` before and after remediation; `kernel.unprivileged_userns_clone=1`; `user.max_user_namespaces=31401`. Bubblewrap is mode 0755, not setuid.
- Ubuntu packages installed in the guest: `apparmor-profiles` and `apparmor-utils` `4.0.1really4.0.1-0ubuntu0.24.04.8`.
- Packaged profile: `/usr/share/apparmor/extra-profiles/bwrap-userns-restrict`, SHA-256 `11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9`. No `bwrap` or `unpriv_bwrap` profile was loaded before installation; no local override files existed. The default `unprivileged_userns` profile was loaded and enforcing.

Before remediation, the kernel audit log recorded `apparmor="DENIED" operation="open"` for `comm="bwrap"`, `name="proc/<pid>/uid_map"`, `requested_mask="wr"`, under profile `unprivileged_userns`. This confirmed why Bubblewrap's unprivileged user-map setup failed. After inspecting the official Ubuntu profile and confirming there were no conflicting Bubblewrap profiles, the following guest-only actions were taken:

```sh
sudo apt-get install --yes apparmor-profiles apparmor-utils
sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
```

The loaded profiles were `bwrap (enforce)` and `unpriv_bwrap (enforce)`. The profile is attached specifically to `/usr/bin/bwrap`; the parent permits namespace setup, while executed children stack into `unpriv_bwrap`, whose policy denies capabilities. The child policy is broad for file, mount, network, and userns operations, so it is not the sandbox by itself. Bubblewrap's namespace and mount configuration remains required. No host setting changed, and the global AppArmor restriction remained `1`.

The post-load ordinary-user smoke used Bubblewrap with required user, mount, PID, IPC, UTS, and network namespace options, `--disable-userns --assert-userns-disabled`, a read-only `/usr`, runtime symlinks, fresh `/proc` and `/dev`, and private `/tmp`. It succeeded. The executed child reported `bwrap//&unpriv_bwrap (enforce)`, `NoNewPrivs=1`, and zero `CapEff`, `CapPrm`, `CapBnd`, `CapInh`, and `CapAmb`.

## Test results

The trusted Python controller ran as EUID 501, outside Bubblewrap, created disposable synthetic files/canaries, and independently inspected host-side results. The final JSON record is [`m0-20261011-ubuntu-24.04-arm64.json`](m0-20261011-ubuntu-24.04-arm64.json). **41 PASS, 0 FAIL, 0 BLOCKED, 0 NOT TESTED.** It includes the exact Bubblewrap argument vectors, output, environment facts, package versions, and profile hash.

| Area | Result and evidence |
|---|---|
| Namespaces | User, mount, PID, IPC, UTS, and network namespaces each worked unprivileged and together. |
| Identity/capabilities | UID map `501 -> inner 0`, GID map `1000 -> inner 0`. Child had all five capability sets zero and `NoNewPrivs=1` under the enforced distro child profile. |
| Nested user namespaces | A child could create a nested userns when the flag was omitted; it could not when `--disable-userns --assert-userns-disabled` was set. |
| Exact-file writes | In-place content modification succeeded; sibling creation, unlink, rename, and atomic replacement were denied by the read-only parent. |
| Directory writes | Create, modify, delete, rename, and atomic replacement succeeded in the authorized writable directory. |
| Nested mount precedence | A read-only file bind over a writable directory denied writes to that file while a neighboring write succeeded. |
| Path and stage | Host canary, original checkout path, absolute and relative traversal, and escaping symlink chain were inaccessible. A copied stage broke a synthetic hard-link alias. |
| Raw hard-link behavior | A deliberately raw-bound source hard link exposed the synthetic canary and an exact-file write changed the linked external inode. This is an observed hazard: staging must copy file contents before mounting. |
| Environment and FDs | `--clearenv` hid a synthetic inherited environment marker. Bubblewrap preserved an explicitly passed canary FD; a launch with `close_fds` blocked it. The AutoCage supervisor must enforce this before starting Bubblewrap. |
| Network and sockets | Synthetic controller connections to guest loopback and interface listeners succeeded as positive controls; the sandbox and a child could not reach them or reserved TEST-NET-1. A host Unix socket was not mounted/reachable. No public service was contacted. |
| Timeout/descendants | A bounded sleeping command started, timed out, and its process group had no live processes after teardown. |
| Python runtime | A two-test pytest fixture passed with read-only `/usr`, `/etc`, runtime aliases, minimal `/dev`, private `/proc`, and private `/tmp`; it also passed with `/etc` omitted. |

The first full run had two harness failures: the code expected UID-map columns in reverse order, and it expected Bubblewrap to scrub a descriptor intentionally passed to it. Linux `uid_map` rows are parent ID then child ID, so the expected map was corrected. The FD test was changed to preserve the exposure as a documented Bubblewrap limitation and separately verify `close_fds` blocks the canary. Neither expected security property was weakened: the final test proves both the raw leak and the required safe-launch mitigation.

## Write-policy implications

Bubblewrap mounts support the planned useful primitives, with an important semantic limit:

- An exact writable file mount supports in-place writes, not directory-entry operations such as create, unlink, rename, or atomic replacement when its parent remains read-only.
- A writable directory mount supports normal editor save behavior and descendant create/delete/rename, but recursively grants those operations throughout that directory.
- A nested read-only file mount can protect a known file under a writable directory while adjacent files remain writable.

The policy representation must therefore distinguish file-content writes from parent-directory namespace operations. For tasks requiring editor-style atomic save, create, delete, or rename, a file-only grant is insufficient. The next implementation must not silently interpret it as a full file-write capability.

## Reproduction

On a clean supported guest, follow [`../README.md`](../README.md): create an ARM64 Ubuntu 24.04 Lima VM with `--mount-none`, verify `mounts: null`, copy only `experiments/m0-linux-feasibility`, and run `setup/install-guest-deps.sh` as the ordinary guest user. The script checks for conflicting loaded Bubblewrap profiles before package installation, installs the two official Ubuntu AppArmor packages and the free M0/M1 test/build tools, loads only the packaged profile, verifies the global restriction is still enabled and both profiles enforce, then runs an unprivileged namespace/profile/capability smoke. Copy the harness into the guest and run:

```sh
limactl shell autocage-m0 -- python3 /tmp/m0-linux-feasibility/scripts/run_m0.py \
  --output /tmp/m0-result.json
```

Copy the JSON record back to the host repository. The harness contacts no external service and uses synthetic disposable fixtures. Lima setup now uses `--containerd=none`; the original VM had unused default Lima container tooling, which was outside this experiment.

## Limits and gate

M0 does not test kernel or Bubblewrap escape resistance, hard CPU/memory/process limits, every filesystem race, broad real-repository behavior, or production supervisor code. `/usr` and `/etc` mounts were read-only but broader than a final least-exposure runtime. A file descriptor explicitly inherited by Bubblewrap remains accessible until AutoCage closes it. The official AppArmor profile is an authorization prerequisite, not a substitute for isolation.

The Linux feasibility gate passed for this named configuration. The minimal M1 runner was subsequently implemented and passed its separately reported Linux test suite. Optimizer, real-agent support, remote networking, and production-grade availability isolation remain out of scope; see the [M1 report](../../m1-runner/REPORT.md).
