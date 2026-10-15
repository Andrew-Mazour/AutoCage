use crate::backend::bubblewrap::{BubblewrapBackend, ReadOnlyMount};
use crate::cli::CommandSpec;
use crate::error::{AutoCageError, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const REQUIRED_PROFILE: &str = "bwrap//&unpriv_bwrap (enforce)";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostFacts {
    pub distribution: String,
    pub ubuntu_version: String,
    pub architecture: String,
    pub kernel: String,
    pub euid: u32,
    pub egid: u32,
    pub bubblewrap_path: PathBuf,
    pub bubblewrap_version: String,
    pub apparmor_enabled: String,
    pub apparmor_userns_restricted: String,
    pub child_profile: String,
    pub child_capabilities: BTreeMap<String, String>,
    pub child_uid_map: String,
    pub child_gid_map: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChildProbe {
    namespace_links: BTreeMap<String, String>,
    uid_map: String,
    gid_map: String,
    apparmor_profile: String,
    capabilities: BTreeMap<String, String>,
    no_new_privs: String,
    nested_userns_allowed: bool,
    nested_userns_errno: Option<i32>,
    has_default_route: bool,
}

pub fn check() -> Result<HostFacts> {
    if !cfg!(target_os = "linux") {
        return Err(fail("AutoCage enforcement is supported only on Linux"));
    }
    if std::env::consts::ARCH != "aarch64" {
        return Err(fail(format!(
            "M1 is validated only for ARM64 Linux; this process reports {}",
            std::env::consts::ARCH
        )));
    }
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    if euid == 0 {
        return Err(fail(
            "refusing to run as root; unprivileged namespace isolation is required",
        ));
    }

    let os_release =
        parse_os_release(&fs::read_to_string("/etc/os-release").map_err(|error| {
            AutoCageError::io(ErrorKind::Preflight, "read /etc/os-release", error)
        })?);
    let distribution = os_release.get("ID").cloned().unwrap_or_default();
    let ubuntu_version = os_release.get("VERSION_ID").cloned().unwrap_or_default();
    if distribution != "ubuntu" || ubuntu_version != "24.04" {
        return Err(fail(format!(
            "unsupported distribution {distribution:?} {ubuntu_version:?}; M1 supports Ubuntu 24.04"
        )));
    }

    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|error| AutoCageError::io(ErrorKind::Preflight, "read kernel version", error))?
        .trim()
        .to_owned();
    if parse_kernel_version(&kernel).map_or(true, |version| version < (6, 8)) {
        return Err(fail(format!(
            "kernel {kernel} is unsupported; Linux 6.8 or later is required"
        )));
    }

    let apparmor_enabled = read_trimmed("/sys/module/apparmor/parameters/enabled")?;
    if apparmor_enabled != "Y" {
        return Err(fail("AppArmor is not enabled"));
    }
    let apparmor_userns_restricted =
        read_trimmed("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")?;
    if apparmor_userns_restricted != "1" {
        return Err(fail(
            "kernel.apparmor_restrict_unprivileged_userns must remain enabled (value 1)",
        ));
    }
    let max_userns = read_trimmed("/proc/sys/user/max_user_namespaces")?;
    if max_userns.parse::<u64>().unwrap_or(0) == 0 {
        return Err(fail("user.max_user_namespaces is zero or unavailable"));
    }

    let bubblewrap_path = PathBuf::from("/usr/bin/bwrap");
    validate_system_executable(&bubblewrap_path, "Bubblewrap")?;
    validate_system_executable(PathBuf::from("/usr/bin/diff").as_path(), "diffutils")?;
    let version_output = Command::new(&bubblewrap_path)
        .arg("--version")
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| AutoCageError::io(ErrorKind::Preflight, "run bwrap --version", error))?;
    if !version_output.status.success() {
        return Err(fail(format!(
            "Bubblewrap version probe failed: {}",
            String::from_utf8_lossy(&version_output.stderr).trim()
        )));
    }
    let bubblewrap_version = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_owned();
    if !supports_assert_userns_disabled(&bubblewrap_version) {
        return Err(fail(format!(
            "Bubblewrap 0.9.0 or later is required for --assert-userns-disabled; found {bubblewrap_version}"
        )));
    }

    let current_exe = std::env::current_exe().map_err(|error| {
        AutoCageError::io(ErrorKind::Preflight, "resolve AutoCage executable", error)
    })?;
    let backend = BubblewrapBackend {
        binary: bubblewrap_path.clone(),
    };
    let spec = CommandSpec {
        program: OsString::from("/autocage-probe"),
        args: vec!["__preflight_probe".into()],
    };
    let mut command = backend.command(
        &crate::policy::ExecutionPolicy::baseline(),
        None,
        &[ReadOnlyMount {
            source: current_exe,
            destination: "/autocage-probe".to_owned(),
        }],
        &spec,
    )?;
    let output = command.output().map_err(|error| {
        AutoCageError::io(
            ErrorKind::Preflight,
            "launch required Bubblewrap namespace probe",
            error,
        )
    })?;
    if !output.status.success() {
        return Err(fail(format!(
            "required Bubblewrap/AppArmor namespace probe failed (status {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let child: ChildProbe = serde_json::from_slice(&output.stdout).map_err(|error| {
        AutoCageError::new(
            ErrorKind::Preflight,
            format!(
                "could not parse Bubblewrap child probe: {error}; output={:?}",
                output.stdout
            ),
        )
    })?;

    validate_probe(&child, euid, egid)?;
    Ok(HostFacts {
        distribution,
        ubuntu_version,
        architecture: std::env::consts::ARCH.to_owned(),
        kernel,
        euid,
        egid,
        bubblewrap_path,
        bubblewrap_version,
        apparmor_enabled,
        apparmor_userns_restricted,
        child_profile: child.apparmor_profile,
        child_capabilities: child.capabilities,
        child_uid_map: child.uid_map,
        child_gid_map: child.gid_map,
    })
}

fn validate_probe(child: &ChildProbe, euid: u32, egid: u32) -> Result<()> {
    if child.apparmor_profile != REQUIRED_PROFILE {
        return Err(fail(format!(
            "sandbox child has unexpected AppArmor profile {:?}; expected {REQUIRED_PROFILE:?}",
            child.apparmor_profile
        )));
    }
    if child.no_new_privs != "1" {
        return Err(fail(format!(
            "sandbox child NoNewPrivs is {}, expected 1",
            child.no_new_privs
        )));
    }
    for key in ["CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"] {
        if child.capabilities.get(key).map(String::as_str) != Some("0000000000000000") {
            return Err(fail(format!(
                "sandbox child capability set {key} is not empty: {:?}",
                child.capabilities.get(key)
            )));
        }
    }
    if child.nested_userns_allowed {
        return Err(fail("sandbox child could create a nested user namespace"));
    }
    if child.has_default_route {
        return Err(fail(
            "sandbox network namespace unexpectedly has a default route",
        ));
    }
    if parse_id_map(&child.uid_map)? != [(euid, 0, 1)] {
        return Err(fail(format!(
            "sandbox UID map is not limited to caller {euid}: {:?}",
            child.uid_map
        )));
    }
    if parse_id_map(&child.gid_map)? != [(egid, 0, 1)] {
        return Err(fail(format!(
            "sandbox GID map is not limited to caller {egid}: {:?}",
            child.gid_map
        )));
    }

    for name in ["user", "mnt", "pid", "ipc", "uts", "net"] {
        let host_path = PathBuf::from(format!("/proc/self/ns/{name}"));
        let host_link = fs::read_link(&host_path).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Preflight,
                format!("read {name} namespace"),
                error,
            )
        })?;
        let child_link = child
            .namespace_links
            .get(name)
            .ok_or_else(|| fail(format!("sandbox probe omitted the {name} namespace")))?;
        if host_link.to_string_lossy() == child_link.as_str() {
            return Err(fail(format!("{name} namespace was not isolated")));
        }
    }
    Ok(())
}

fn parse_id_map(raw: &str) -> Result<Vec<(u32, u32, u32)>> {
    raw.lines()
        .map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(fail(format!("invalid namespace ID map row {line:?}")));
            }
            Ok((
                fields[0]
                    .parse()
                    .map_err(|_| fail(format!("invalid namespace ID map row {line:?}")))?,
                fields[1]
                    .parse()
                    .map_err(|_| fail(format!("invalid namespace ID map row {line:?}")))?,
                fields[2]
                    .parse()
                    .map_err(|_| fail(format!("invalid namespace ID map row {line:?}")))?,
            ))
        })
        .collect()
}

fn parse_os_release(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_owned(), value.trim_matches('"').to_owned()))
        })
        .collect()
}

fn parse_kernel_version(raw: &str) -> Option<(u32, u32)> {
    let mut parts = raw.split(['.', '-']);
    let major = parts.next()?;
    let minor = parts.next()?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn supports_assert_userns_disabled(version: &str) -> bool {
    let Some(raw) = version.strip_prefix("bubblewrap ") else {
        return false;
    };
    let mut parts = raw.split('.');
    let major = parts.next().and_then(|part| part.parse::<u32>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u32>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 0 || minor >= 9)
}

fn read_trimmed(path: &str) -> Result<String> {
    fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .map_err(|error| AutoCageError::io(ErrorKind::Preflight, format!("read {path}"), error))
}

fn validate_system_executable(path: &std::path::Path, name: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AutoCageError::io(
            ErrorKind::Preflight,
            format!("inspect required {name} executable {}", path.display()),
            error,
        )
    })?;
    let mode = metadata.mode();
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || mode & 0o022 != 0
        || mode & 0o111 == 0
        || mode & 0o6000 != 0
    {
        return Err(fail(format!(
            "required {name} executable {} must be a root-owned regular file, executable, not group/world writable, and not setuid/setgid (uid={}, mode={:o})",
            path.display(),
            metadata.uid(),
            mode & 0o7777
        )));
    }
    Ok(())
}

fn fail(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Preflight, message)
}

pub fn emit_child_probe() -> Result<()> {
    let mut namespace_links = BTreeMap::new();
    for name in ["user", "mnt", "pid", "ipc", "uts", "net"] {
        let link = fs::read_link(format!("/proc/self/ns/{name}")).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Preflight,
                format!("read child {name} namespace"),
                error,
            )
        })?;
        namespace_links.insert(name.to_owned(), link.to_string_lossy().into_owned());
    }
    let uid_map = read_trimmed("/proc/self/uid_map")?;
    let gid_map = read_trimmed("/proc/self/gid_map")?;
    let apparmor_profile = read_trimmed("/proc/self/attr/current")?;
    let mut capabilities = BTreeMap::new();
    let mut no_new_privs = None;
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| AutoCageError::io(ErrorKind::Preflight, "read child status", error))?;
    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if matches!(key, "CapEff" | "CapPrm" | "CapBnd" | "CapInh" | "CapAmb") {
                capabilities.insert(key.to_owned(), value.trim().to_owned());
            } else if key == "NoNewPrivs" {
                no_new_privs = Some(value.trim().to_owned());
            }
        }
    }
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    let nested_userns_errno = if rc == 0 {
        None
    } else {
        Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    };
    let routes = fs::read_to_string("/proc/net/route")
        .map_err(|error| AutoCageError::io(ErrorKind::Preflight, "read sandbox routes", error))?;
    let has_default_route = routes
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(1) == Some("00000000"));
    let child = ChildProbe {
        namespace_links,
        uid_map,
        gid_map,
        apparmor_profile,
        capabilities,
        no_new_privs: no_new_privs.unwrap_or_default(),
        nested_userns_allowed: rc == 0,
        nested_userns_errno,
        has_default_route,
    };
    serde_json::to_writer(std::io::stdout().lock(), &child).map_err(|error| {
        AutoCageError::new(
            ErrorKind::Preflight,
            format!("serialize preflight probe: {error}"),
        )
    })?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_version_without_distribution_suffix() {
        assert_eq!(parse_kernel_version("6.8.0-142-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("6.7.12"), Some((6, 7)));
    }

    #[test]
    fn version_gate_requires_assert_userns_option() {
        assert!(supports_assert_userns_disabled("bubblewrap 0.9.0"));
        assert!(supports_assert_userns_disabled("bubblewrap 1.0.0"));
        assert!(!supports_assert_userns_disabled("bubblewrap 0.8.0"));
        assert!(!supports_assert_userns_disabled("unknown"));
    }

    #[test]
    fn reads_linux_uid_map_column_order() {
        assert_eq!(parse_id_map("501 0 1\n").unwrap(), vec![(501, 0, 1)]);
    }
}
