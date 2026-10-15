use crate::error::{AutoCageError, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Directory,
    RegularFile,
    Symlink,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug)]
pub struct WorkspaceSnapshot {
    pub baseline: PathBuf,
    pub stage: PathBuf,
    pub omissions: Vec<String>,
    pub before_manifest: Vec<ManifestEntry>,
    pub before_hash: String,
}

#[derive(Debug, Clone)]
pub struct ProtectedRoot {
    pub source: PathBuf,
    pub destination: String,
    pub relative_path: String,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceOutcome {
    pub after_manifest: Vec<ManifestEntry>,
    pub after_hash: String,
    pub changed_paths: Vec<String>,
}

#[derive(Debug)]
struct OwnedFd(RawFd);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

pub fn prepare(source: &Path, run_dir: &Path) -> Result<WorkspaceSnapshot> {
    let source = source
        .canonicalize()
        .map_err(|error| AutoCageError::io(ErrorKind::Stage, "resolve workspace", error))?;
    if !source.is_dir() {
        return Err(stage_error("workspace must be a directory"));
    }
    if run_dir.starts_with(&source) {
        return Err(stage_error(
            "run directory must not be inside the source workspace",
        ));
    }

    let baseline = run_dir.join("baseline");
    let stage = run_dir.join("stage");
    let mut omissions = Vec::new();
    create_private_directory(&baseline)?;
    let root_fd = open_directory(&source)?;
    copy_directory(root_fd.0, &baseline, Path::new(""), &mut omissions)?;

    create_private_directory(&stage)?;
    let baseline_fd = open_directory(&baseline)?;
    copy_directory(baseline_fd.0, &stage, Path::new(""), &mut Vec::new())?;

    let before_manifest = manifest_tree(&baseline)?;
    let before_hash = manifest_hash(&before_manifest)?;
    Ok(WorkspaceSnapshot {
        baseline,
        stage,
        omissions,
        before_manifest,
        before_hash,
    })
}

pub fn finish(snapshot: &WorkspaceSnapshot, run_dir: &Path) -> Result<(WorkspaceOutcome, PathBuf)> {
    let after_manifest = manifest_tree(&snapshot.stage)?;
    let after_hash = manifest_hash(&after_manifest)?;
    let before = snapshot
        .before_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let after = after_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let paths = before
        .keys()
        .chain(after.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let changed_paths = paths
        .into_iter()
        .filter(|path| before.get(path) != after.get(path))
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let patch_path = run_dir.join("changes.patch");
    write_review_patch(
        snapshot,
        &after_manifest,
        &changed_paths,
        &patch_path,
        run_dir,
    )?;
    Ok((
        WorkspaceOutcome {
            after_manifest,
            after_hash,
            changed_paths,
        },
        patch_path,
    ))
}

pub fn protected_verifier_roots(
    snapshot: &WorkspaceSnapshot,
    requested: &[PathBuf],
) -> Result<Vec<ProtectedRoot>> {
    let mut roots: Vec<ProtectedRoot> = Vec::new();
    let mut names = BTreeSet::new();
    for path in requested {
        if path.is_absolute()
            || path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(stage_error(format!(
                "verifier readonly root must be a normalized relative path: {}",
                path.display()
            )));
        }
        let name = display_relative(path);
        if !names.insert(name.clone()) {
            return Err(stage_error(format!(
                "duplicate verifier readonly root: {name}"
            )));
        }
        for existing in &roots {
            if name == existing.relative_path
                || name.starts_with(&format!("{}/", existing.relative_path))
                || existing.relative_path.starts_with(&format!("{name}/"))
            {
                return Err(stage_error(format!(
                    "overlapping verifier readonly roots: {name} and {}",
                    existing.relative_path
                )));
            }
        }

        let mut current = snapshot.baseline.clone();
        for component in path.components() {
            let Component::Normal(name) = component else {
                unreachable!("validated normal path")
            };
            current.push(name);
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                AutoCageError::io(
                    ErrorKind::Stage,
                    format!("inspect verifier readonly path {}", path.display()),
                    error,
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(stage_error(format!(
                    "verifier readonly root traverses a symlink: {}",
                    path.display()
                )));
            }
        }
        roots.push(ProtectedRoot {
            source: current,
            destination: format!("/workspace/{name}"),
            relative_path: name,
        });
    }
    Ok(roots)
}

fn copy_directory(
    source_fd: RawFd,
    destination: &Path,
    relative: &Path,
    omissions: &mut Vec<String>,
) -> Result<()> {
    let listing = PathBuf::from(format!("/proc/self/fd/{source_fd}"));
    let entries = fs::read_dir(listing)
        .map_err(|error| AutoCageError::io(ErrorKind::Stage, "list source directory", error))?;
    let mut names = entries
        .map(|entry| {
            entry
                .map(|item| item.file_name())
                .map_err(|error| AutoCageError::io(ErrorKind::Stage, "read directory entry", error))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();

    for name in names {
        let name_text = name
            .to_str()
            .ok_or_else(|| stage_error("non-UTF-8 workspace paths are not supported in M1"))?;
        if name_text.chars().any(char::is_control) {
            return Err(stage_error(format!(
                "workspace path contains a control character: {name_text:?}"
            )));
        }
        let child_rel = relative.join(name_text);
        if let Some(reason) = omission_reason(&child_rel) {
            omissions.push(format!("{} ({reason})", display_relative(&child_rel)));
            continue;
        }
        let name_c = CString::new(name.as_bytes())
            .map_err(|_| stage_error("workspace filename contains an embedded NUL"))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                source_fd,
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(AutoCageError::io(
                ErrorKind::Stage,
                format!(
                    "inspect {} without following symlinks",
                    display_relative(&child_rel)
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let stat = unsafe { stat.assume_init() };
        let target = destination.join(&name);
        let file_kind = stat.st_mode & libc::S_IFMT;
        match file_kind {
            libc::S_IFDIR => {
                let fd = openat_directory(source_fd, &name_c, &child_rel)?;
                create_private_directory(&target)?;
                copy_directory(fd.0, &target, &child_rel, omissions)?;
            }
            libc::S_IFREG => {
                let fd = openat_file(source_fd, &name_c, &child_rel)?;
                let mut input = unsafe { File::from_raw_fd(fd.0) };
                std::mem::forget(fd);
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(safe_file_mode(stat.st_mode))
                    .open(&target)
                    .map_err(|error| {
                        AutoCageError::io(
                            ErrorKind::Stage,
                            format!("create staged file {}", display_relative(&child_rel)),
                            error,
                        )
                    })?;
                std::io::copy(&mut input, &mut output).map_err(|error| {
                    AutoCageError::io(
                        ErrorKind::Stage,
                        format!("copy staged file {}", display_relative(&child_rel)),
                        error,
                    )
                })?;
                output.sync_all().map_err(|error| {
                    AutoCageError::io(ErrorKind::Stage, "flush staged file", error)
                })?;
            }
            libc::S_IFLNK => {
                let target_text = read_link_at(source_fd, &name_c, &child_rel)?;
                validate_symlink_target(&target_text, &child_rel)?;
                symlink(&target_text, &target).map_err(|error| {
                    AutoCageError::io(
                        ErrorKind::Stage,
                        format!("copy symlink {}", display_relative(&child_rel)),
                        error,
                    )
                })?;
            }
            _ => {
                return Err(stage_error(format!(
                    "unsupported special file in workspace: {}",
                    display_relative(&child_rel)
                )))
            }
        }
    }
    Ok(())
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| stage_error("workspace path contains an embedded NUL"))?;
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(AutoCageError::io(
            ErrorKind::Stage,
            format!(
                "open directory {} without following symlinks",
                path.display()
            ),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(OwnedFd(fd))
}

fn openat_directory(parent: RawFd, name: &CString, relative: &Path) -> Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(AutoCageError::io(
            ErrorKind::Stage,
            format!(
                "open directory {} without following symlinks",
                display_relative(relative)
            ),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(OwnedFd(fd))
}

fn openat_file(parent: RawFd, name: &CString, relative: &Path) -> Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(AutoCageError::io(
            ErrorKind::Stage,
            format!(
                "open file {} without following symlinks",
                display_relative(relative)
            ),
            std::io::Error::last_os_error(),
        ));
    }
    let opened = OwnedFd(fd);
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(opened.0, stat.as_mut_ptr()) } != 0 {
        return Err(AutoCageError::io(
            ErrorKind::Stage,
            format!("verify opened file {}", display_relative(relative)),
            std::io::Error::last_os_error(),
        ));
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(stage_error(format!(
            "workspace entry changed to a non-regular file while staging: {}",
            display_relative(relative)
        )));
    }
    Ok(opened)
}

fn read_link_at(parent: RawFd, name: &CString, relative: &Path) -> Result<PathBuf> {
    let mut bytes = vec![0u8; 4096];
    loop {
        let count = unsafe {
            libc::readlinkat(
                parent,
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(AutoCageError::io(
                ErrorKind::Stage,
                format!("read symlink {}", display_relative(relative)),
                std::io::Error::last_os_error(),
            ));
        }
        let count = count as usize;
        if count < bytes.len() {
            bytes.truncate(count);
            let target = String::from_utf8(bytes)
                .map_err(|_| stage_error("non-UTF-8 symlink targets are not supported in M1"))?;
            return Ok(PathBuf::from(target));
        }
        if bytes.len() >= 64 * 1024 {
            return Err(stage_error("symlink target is too long"));
        }
        bytes.resize(bytes.len() * 2, 0);
    }
}

fn validate_symlink_target(target: &Path, link_path: &Path) -> Result<()> {
    if target.is_absolute()
        || target
            .components()
            .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
    {
        return Err(stage_error(format!(
            "absolute symlink is not staged: {} -> {}",
            display_relative(link_path),
            target.display()
        )));
    }

    let mut resolved = link_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => resolved.push(part.to_os_string()),
            Component::ParentDir if resolved.pop().is_some() => {}
            Component::ParentDir => {
                return Err(stage_error(format!(
                    "symlink target escapes the staged workspace: {} -> {}",
                    display_relative(link_path),
                    target.display()
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                unreachable!("absolute paths rejected above")
            }
        }
    }
    Ok(())
}

fn safe_file_mode(source_mode: libc::mode_t) -> u32 {
    (source_mode & 0o777 & !0o6000) | 0o600
}

fn create_private_directory(path: &Path) -> Result<()> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| stage_error("directory path contains an embedded NUL"))?;
    let rc = unsafe { libc::mkdir(path_c.as_ptr(), 0o700) };
    if rc != 0 {
        return Err(AutoCageError::io(
            ErrorKind::Stage,
            format!("create private directory {}", path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        AutoCageError::io(
            ErrorKind::Stage,
            format!("secure {}", path.display()),
            error,
        )
    })
}

fn omission_reason(path: &Path) -> Option<&'static str> {
    let components = path.components().filter_map(|part| match part {
        Component::Normal(name) => name.to_str(),
        _ => None,
    });
    let parts = components.collect::<Vec<_>>();
    let name = parts.last().copied().unwrap_or_default();
    if name == ".git" {
        return Some("repository metadata");
    }
    if parts.len() == 1
        && matches!(
            name,
            ".ssh" | ".aws" | ".azure" | ".kube" | ".gnupg" | ".config"
        )
    {
        return Some("root-level credential/config directory");
    }
    if matches!(name, ".npmrc" | ".pypirc" | ".netrc" | ".git-credentials") {
        return Some("credential file");
    }
    if matches!(name, "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa") {
        return Some("recognized private-key filename");
    }
    if name == ".env"
        || (name.starts_with(".env.") && !name.ends_with(".example") && !name.ends_with(".sample"))
    {
        return Some("environment secret file");
    }
    None
}

pub fn manifest_tree(root: &Path) -> Result<Vec<ManifestEntry>> {
    manifest_tree_with_omissions(root, false)
}

/// Fingerprint exactly the files that staging makes visible. This lets a
/// pre-execution suggestion bind to the staged snapshot without traversing
/// omitted `.git` data or host credential paths.
pub fn source_manifest_hash(root: &Path) -> Result<String> {
    manifest_hash(&manifest_tree_with_omissions(root, true)?)
}

fn manifest_tree_with_omissions(root: &Path, omit_protected: bool) -> Result<Vec<ManifestEntry>> {
    let mut entries = Vec::new();
    manifest_directory(root, root, Path::new(""), &mut entries, omit_protected)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn manifest_directory(
    root: &Path,
    directory: &Path,
    relative: &Path,
    entries: &mut Vec<ManifestEntry>,
    omit_protected: bool,
) -> Result<()> {
    let listing = fs::read_dir(directory).map_err(|error| {
        AutoCageError::io(
            ErrorKind::Stage,
            format!("list {}", directory.display()),
            error,
        )
    })?;
    let mut names = listing
        .map(|entry| {
            entry
                .map(|item| item.file_name())
                .map_err(|error| AutoCageError::io(ErrorKind::Stage, "read staged entry", error))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    for name in names {
        let name_text = name
            .to_str()
            .ok_or_else(|| stage_error("non-UTF-8 staged paths are not supported in M1"))?;
        if name_text.chars().any(char::is_control) {
            return Err(stage_error(format!(
                "staged path contains a control character: {name_text:?}"
            )));
        }
        let child_rel = relative.join(name_text);
        if omit_protected && omission_reason(&child_rel).is_some() {
            continue;
        }
        let full_path = root.join(&child_rel);
        let meta = fs::symlink_metadata(&full_path).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Stage,
                format!("inspect {}", display_relative(&child_rel)),
                error,
            )
        })?;
        let mode = if omit_protected && meta.is_dir() {
            0o700
        } else if omit_protected && meta.is_file() {
            safe_file_mode(meta.permissions().mode())
        } else {
            meta.permissions().mode() & 0o7777
        };
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&full_path).map_err(|error| {
                AutoCageError::io(ErrorKind::Stage, "read staged symlink", error)
            })?;
            let bytes = target.as_os_str().as_bytes();
            entries.push(ManifestEntry {
                path: display_relative(&child_rel),
                kind: EntryKind::Symlink,
                mode,
                size: bytes.len() as u64,
                sha256: Some(hash_bytes(bytes)),
            });
        } else if meta.is_dir() {
            entries.push(ManifestEntry {
                path: display_relative(&child_rel),
                kind: EntryKind::Directory,
                mode,
                size: 0,
                sha256: None,
            });
            manifest_directory(root, &full_path, &child_rel, entries, omit_protected)?;
        } else if meta.is_file() {
            let data = read_regular_nofollow(&full_path)?;
            entries.push(ManifestEntry {
                path: display_relative(&child_rel),
                kind: EntryKind::RegularFile,
                mode,
                size: data.len() as u64,
                sha256: Some(hash_bytes(&data)),
            });
        } else {
            entries.push(ManifestEntry {
                path: display_relative(&child_rel),
                kind: EntryKind::Special,
                mode,
                size: 0,
                sha256: None,
            });
        }
    }
    Ok(())
}

fn read_regular_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            AutoCageError::io(ErrorKind::Stage, format!("read {}", path.display()), error)
        })?;
    let metadata = file.metadata().map_err(|error| {
        AutoCageError::io(ErrorKind::Stage, "inspect opened staged file", error)
    })?;
    if !metadata.is_file() {
        return Err(stage_error(format!(
            "staged path is not a regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        AutoCageError::io(ErrorKind::Stage, format!("read {}", path.display()), error)
    })?;
    Ok(bytes)
}

pub fn manifest_hash(entries: &[ManifestEntry]) -> Result<String> {
    let bytes = serde_json::to_vec(entries).map_err(|error| {
        AutoCageError::new(
            ErrorKind::Record,
            format!("serialize workspace manifest: {error}"),
        )
    })?;
    Ok(hash_bytes(&bytes))
}

fn write_review_patch(
    snapshot: &WorkspaceSnapshot,
    after_manifest: &[ManifestEntry],
    changed_paths: &[String],
    patch_path: &Path,
    run_dir: &Path,
) -> Result<()> {
    let before = snapshot
        .before_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let after = after_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut patch = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(patch_path)
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "create patch file", error))?;
    let mut temp_index = 0usize;
    for path in changed_paths {
        let before_entry = before.get(path.as_str()).copied();
        let after_entry = after.get(path.as_str()).copied();
        let before_regular = before_entry
            .map(|entry| entry.kind == EntryKind::RegularFile)
            .unwrap_or(false);
        let after_regular = after_entry
            .map(|entry| entry.kind == EntryKind::RegularFile)
            .unwrap_or(false);
        if !before_regular && !after_regular {
            if before_entry != after_entry {
                writeln!(
                    patch,
                    "Non-file entry changed: {path} ({before_entry:?} -> {after_entry:?})"
                )
                .map_err(|error| {
                    AutoCageError::io(ErrorKind::Record, "write non-file change summary", error)
                })?;
            }
            continue;
        }
        if let (Some(before_entry), Some(after_entry)) = (before_entry, after_entry) {
            if before_entry.mode != after_entry.mode {
                writeln!(
                    patch,
                    "Mode changed: {path} ({:o} -> {:o})",
                    before_entry.mode, after_entry.mode
                )
                .map_err(|error| {
                    AutoCageError::io(ErrorKind::Record, "write mode summary", error)
                })?;
            }
        }
        let before_bytes = if before_regular {
            read_regular_nofollow(&snapshot.baseline.join(path))?
        } else {
            Vec::new()
        };
        let after_bytes = if after_regular {
            read_regular_nofollow(&snapshot.stage.join(path))?
        } else {
            Vec::new()
        };
        if before_bytes.contains(&0) || after_bytes.contains(&0) {
            writeln!(patch, "Binary file changed: {path}").map_err(|error| {
                AutoCageError::io(ErrorKind::Record, "write binary patch summary", error)
            })?;
            continue;
        }
        let left = run_dir.join(format!(".patch-left-{temp_index}"));
        let right = run_dir.join(format!(".patch-right-{temp_index}"));
        temp_index += 1;
        fs::write(&left, &before_bytes)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "write patch input", error))?;
        fs::write(&right, &after_bytes)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "write patch input", error))?;
        let diff = Command::new("/usr/bin/diff")
            .arg("--unified=3")
            .arg(format!("--label=a/{path}"))
            .arg(format!("--label=b/{path}"))
            .arg("--")
            .arg(&left)
            .arg(&right)
            .env_clear()
            .output()
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "run diff for patch", error))?;
        if !diff.status.success() && diff.status.code() != Some(1) {
            return Err(AutoCageError::new(
                ErrorKind::Record,
                format!(
                    "diff failed for {path}: {}",
                    String::from_utf8_lossy(&diff.stderr).trim()
                ),
            ));
        }
        patch
            .write_all(&diff.stdout)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "append patch output", error))?;
        fs::remove_file(&left)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "remove patch temp", error))?;
        fs::remove_file(&right)
            .map_err(|error| AutoCageError::io(ErrorKind::Record, "remove patch temp", error))?;
    }
    patch
        .sync_all()
        .map_err(|error| AutoCageError::io(ErrorKind::Record, "flush patch file", error))?;
    Ok(())
}

fn display_relative(path: &Path) -> String {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn hash_bytes(bytes: &[u8]) -> String {
    crate::digest::hex(&Sha256::digest(bytes))
}

fn stage_error(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Stage, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::MetadataExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("autocage-{label}-{}-{stamp}", std::process::id()));
        fs::create_dir(&path).expect("create test root");
        path
    }

    #[test]
    fn copies_files_and_omits_git_and_root_credentials() {
        let root = temp_root("stage");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join(".git")).unwrap();
        fs::create_dir(source.join(".ssh")).unwrap();
        fs::write(source.join(".git/config"), "git metadata").unwrap();
        fs::write(source.join(".ssh/id_ed25519"), "synthetic key").unwrap();
        fs::write(source.join(".env"), "synthetic secret").unwrap();
        fs::write(source.join(".env.example"), "placeholder").unwrap();
        fs::write(source.join("main.py"), "print('ok')\n").unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        let snapshot = prepare(&source, &run_dir).unwrap();
        assert!(snapshot.stage.join("main.py").is_file());
        assert!(!snapshot.stage.join(".git").exists());
        assert!(!snapshot.stage.join(".ssh").exists());
        assert!(!snapshot.stage.join(".env").exists());
        assert!(snapshot.stage.join(".env.example").exists());
        assert_eq!(snapshot.omissions.len(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_absolute_and_escaping_symlinks() {
        let root = temp_root("symlink");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        symlink("../../outside", source.join("escape")).unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        assert!(prepare(&source, &run_dir)
            .unwrap_err()
            .message
            .contains("escapes the staged workspace"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_absolute_symlinks() {
        let root = temp_root("absolute-symlink");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        symlink("/etc/passwd", source.join("escape")).unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        assert!(prepare(&source, &run_dir)
            .unwrap_err()
            .message
            .contains("absolute symlink"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_parent_symlinks_whose_normalized_target_stays_inside_stage() {
        let root = temp_root("internal-parent-symlink");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("docs")).unwrap();
        fs::write(source.join("CHANGELOG.md"), "synthetic changelog\n").unwrap();
        symlink("../CHANGELOG.md", source.join("docs/changelog.md")).unwrap();
        symlink("changelog.md", source.join("docs/changelog-alias.md")).unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();

        let snapshot = prepare(&source, &run_dir).unwrap();
        assert_eq!(
            fs::read_to_string(snapshot.stage.join("docs/changelog.md")).unwrap(),
            "synthetic changelog\n"
        );
        assert_eq!(
            fs::read_to_string(snapshot.stage.join("docs/changelog-alias.md")).unwrap(),
            "synthetic changelog\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copies_regular_files_by_value_and_keeps_safe_relative_symlinks() {
        let root = temp_root("hardlink");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("data"), "initial").unwrap();
        fs::hard_link(source.join("data"), source.join("alias")).unwrap();
        symlink("data", source.join("link")).unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        let snapshot = prepare(&source, &run_dir).unwrap();
        assert_ne!(
            fs::metadata(source.join("data")).unwrap().ino(),
            fs::metadata(snapshot.stage.join("data")).unwrap().ino()
        );
        assert!(fs::symlink_metadata(snapshot.stage.join("link"))
            .unwrap()
            .file_type()
            .is_symlink());
        fs::write(snapshot.stage.join("alias"), "changed").unwrap();
        assert_eq!(fs::read_to_string(source.join("data")).unwrap(), "initial");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_special_files_instead_of_following_them() {
        let root = temp_root("special");
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let fifo = CString::new(source.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let source_fd = open_directory(&source).unwrap();
        assert!(openat_file(
            source_fd.0,
            &CString::new("pipe").unwrap(),
            Path::new("pipe")
        )
        .unwrap_err()
        .message
        .contains("non-regular"));
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        assert!(prepare(&source, &run_dir)
            .unwrap_err()
            .message
            .contains("special file"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_detects_file_changes_without_following_symlinks() {
        let root = temp_root("manifest");
        fs::write(root.join("file"), "before").unwrap();
        let before = manifest_tree(&root).unwrap();
        fs::write(root.join("file"), "after").unwrap();
        let after = manifest_tree(&root).unwrap();
        assert_ne!(before, after);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_fingerprint_matches_staged_inputs_and_ignores_omitted_secrets() {
        let root = temp_root("source-fingerprint");
        let source = root.join("source");
        fs::create_dir_all(source.join(".git/objects")).unwrap();
        fs::create_dir_all(source.join(".ssh")).unwrap();
        fs::write(source.join("src.py"), "visible\n").unwrap();
        fs::write(source.join(".git/objects/private"), "metadata\n").unwrap();
        fs::write(source.join(".ssh/id_ed25519"), "synthetic-secret\n").unwrap();
        fs::write(source.join(".env.local"), "synthetic-secret\n").unwrap();

        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        let snapshot = prepare(&source, &run_dir).unwrap();
        assert_eq!(source_manifest_hash(&source).unwrap(), snapshot.before_hash);
        fs::write(source.join(".git/objects/private"), "changed metadata\n").unwrap();
        fs::write(source.join(".ssh/id_ed25519"), "changed synthetic secret\n").unwrap();
        fs::write(source.join(".env.local"), "changed synthetic secret\n").unwrap();
        assert_eq!(source_manifest_hash(&source).unwrap(), snapshot.before_hash);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verifier_roots_reject_overlap_symlink_traversal_and_parent_paths() {
        let root = temp_root("verifier-roots");
        let source = root.join("source");
        fs::create_dir_all(source.join("tests/sub")).unwrap();
        symlink("tests", source.join("test-link")).unwrap();
        let run_dir = root.join("run");
        create_private_directory(&run_dir).unwrap();
        let snapshot = prepare(&source, &run_dir).unwrap();

        let overlap = protected_verifier_roots(
            &snapshot,
            &[PathBuf::from("tests"), PathBuf::from("tests/sub")],
        )
        .unwrap_err();
        assert!(overlap.message.contains("overlapping"));

        let symlink_path =
            protected_verifier_roots(&snapshot, &[PathBuf::from("test-link")]).unwrap_err();
        assert!(symlink_path.message.contains("symlink"));

        let parent_path =
            protected_verifier_roots(&snapshot, &[PathBuf::from("../outside")]).unwrap_err();
        assert!(parent_path.message.contains("normalized relative path"));
        fs::remove_dir_all(root).unwrap();
    }
}
