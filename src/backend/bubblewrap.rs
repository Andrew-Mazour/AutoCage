use crate::cli::CommandSpec;
use crate::error::{AutoCageError, ErrorKind, Result};
use crate::policy::{ExecutionPolicy, WriteGrant};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct BubblewrapBackend {
    pub binary: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ReadOnlyMount {
    pub source: PathBuf,
    pub destination: String,
}

impl BubblewrapBackend {
    pub fn command(
        &self,
        policy: &ExecutionPolicy,
        stage: Option<&Path>,
        extra_readonly: &[ReadOnlyMount],
        spec: &CommandSpec,
    ) -> Result<Command> {
        let mut args = vec![
            "--die-with-parent".into(),
            "--new-session".into(),
            "--unshare-user".into(),
            "--unshare-pid".into(),
            "--unshare-ipc".into(),
            "--unshare-uts".into(),
            "--unshare-net".into(),
            "--disable-userns".into(),
            "--assert-userns-disabled".into(),
            "--ro-bind".into(),
            "/usr".into(),
            "/usr".into(),
        ];
        for (target, destination) in [
            ("usr/bin", "/bin"),
            ("usr/sbin", "/sbin"),
            ("usr/lib", "/lib"),
            ("usr/lib64", "/lib64"),
        ] {
            args.extend(["--symlink".into(), target.into(), destination.into()]);
        }
        args.extend([
            "--dev".into(),
            "/dev".into(),
            "--proc".into(),
            "/proc".into(),
            "--tmpfs".into(),
            "/tmp".into(),
            "--dir".into(),
            "/tmp/home".into(),
        ]);
        if let Some(stage) = stage {
            policy.validate(stage)?;
            args.extend([
                "--ro-bind".into(),
                stage.as_os_str().to_owned(),
                "/workspace".into(),
            ]);
            // Grant mounts go over a read-only base. Normalized policies do
            // not contain redundant/overlapping writable rules.
            for grant in &policy.write_grants {
                let (source, destination) = match grant {
                    WriteGrant::FileContents(path) | WriteGrant::DirectoryTree(path)
                        if path == Path::new(".") =>
                    {
                        (stage.to_path_buf(), "/workspace".to_owned())
                    }
                    WriteGrant::FileContents(path) | WriteGrant::DirectoryTree(path) => {
                        (stage.join(path), format!("/workspace/{}", path.display()))
                    }
                };
                args.extend(["--bind".into(), source.into_os_string(), destination.into()]);
            }
        }
        // Nested verifier mounts come after the writable workspace mount so
        // their read-only access mode takes precedence, as the M0 canary proved.
        for mount in extra_readonly {
            if !mount.destination.starts_with('/')
                || mount.destination.split('/').any(|part| part == "..")
            {
                return Err(AutoCageError::new(
                    ErrorKind::Policy,
                    format!(
                        "readonly mount destination is not an absolute normalized path: {}",
                        mount.destination
                    ),
                ));
            }
            args.extend([
                "--ro-bind".into(),
                mount.source.as_os_str().to_owned(),
                mount.destination.clone().into(),
            ]);
        }
        args.extend([
            "--chdir".into(),
            if stage.is_some() {
                "/workspace"
            } else {
                "/tmp"
            }
            .into(),
            "--clearenv".into(),
            "--setenv".into(),
            "PATH".into(),
            "/usr/bin:/bin".into(),
            "--setenv".into(),
            "HOME".into(),
            "/tmp/home".into(),
            "--setenv".into(),
            "TMPDIR".into(),
            "/tmp".into(),
            "--setenv".into(),
            "PWD".into(),
            if stage.is_some() {
                "/workspace"
            } else {
                "/tmp"
            }
            .into(),
            "--setenv".into(),
            "LANG".into(),
            "C.UTF-8".into(),
            "--setenv".into(),
            "PYTHONDONTWRITEBYTECODE".into(),
            "1".into(),
            "--".into(),
        ]);
        args.push(spec.program.clone());
        args.extend(spec.args.iter().cloned());

        let mut command = Command::new(&self.binary);
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);

        // CLOEXEC preserves Rust's internal exec-error pipe until exec while
        // ensuring no unrelated supervisor FD reaches Bubblewrap or its child.
        unsafe {
            command.pre_exec(|| {
                let rc = libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                );
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "autocage-backend-{}-{stamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn command_requires_namespaces_and_never_shares_network() {
        let root = temp_dir();
        fs::write(root.join("file"), "x").unwrap();
        let backend = BubblewrapBackend {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let spec = CommandSpec {
            program: "/usr/bin/true".into(),
            args: vec![],
        };
        let command = backend
            .command(&ExecutionPolicy::baseline(), Some(&root), &[], &spec)
            .unwrap();
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for required in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--disable-userns",
            "--assert-userns-disabled",
            "--clearenv",
        ] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }
        assert!(!args.iter().any(|arg| arg == "--share-net"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn launcher_marks_unapproved_inherited_descriptor_close_on_exec() {
        let root = temp_dir();
        let stage = root.join("stage");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("README.md"), "workspace\n").unwrap();
        let canary = root.join("host-fd-canary");
        fs::write(&canary, "AUTOCAGE-M1-FD-CANARY").unwrap();
        let file = File::open(&canary).unwrap();
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );

        let probe = "import os,sys\ntry: data=os.pread(int(sys.argv[1]),4096,0)\nexcept OSError: raise SystemExit(0)\nraise SystemExit(55 if b'AUTOCAGE-M1-FD-CANARY' in data else 0)";
        let spec = CommandSpec {
            program: "/usr/bin/python3".into(),
            args: vec!["-c".into(), probe.into(), fd.to_string().into()],
        };
        let backend = BubblewrapBackend {
            binary: PathBuf::from("/usr/bin/bwrap"),
        };
        let output = backend
            .command(&ExecutionPolicy::baseline(), Some(&stage), &[], &spec)
            .unwrap()
            .output()
            .expect("start sandboxed canary probe");
        assert_eq!(
            output.status.code(),
            Some(0),
            "inherited descriptor exposed the canary: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }
}
