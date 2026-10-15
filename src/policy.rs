use crate::error::{AutoCageError, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "path", rename_all = "snake_case")]
pub enum WriteGrant {
    /// In-place mutation of an existing regular-file inode (including owner-
    /// permitted mode/metadata changes). Directory-entry operations such as
    /// create, unlink, rename, and atomic replacement remain denied.
    FileContents(PathBuf),
    /// Recursive writes, including directory-entry operations, below a path.
    DirectoryTree(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub schema_version: u32,
    pub write_grants: Vec<WriteGrant>,
    pub network_access: bool,
    pub disable_nested_userns: bool,
}

impl ExecutionPolicy {
    /// M1's explicit broad staged-workspace-write ceiling.
    pub fn baseline() -> Self {
        Self::new(vec![WriteGrant::DirectoryTree(PathBuf::from("."))])
    }

    pub fn new(write_grants: Vec<WriteGrant>) -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            write_grants,
            network_access: false,
            disable_nested_userns: true,
        }
    }

    /// Canonical ordering, duplicate removal, and removal of grants subsumed by
    /// an ancestor recursive grant. Positive overlaps have no conflict once
    /// normalized; callers cannot use normalization to widen authority.
    pub fn normalize(&self) -> Result<Self> {
        self.check_global_invariants()?;
        let mut grants = self.write_grants.clone();
        for grant in &grants {
            validate_relative(grant_path(grant))?;
        }
        grants.sort();
        grants.dedup();
        let all_grants = grants.clone();
        grants.retain(|grant| {
            !all_grants.iter().any(|ancestor| {
                ancestor != grant
                    && is_directory_grant(ancestor)
                    && path_is_same_or_child(grant_path(grant), grant_path(ancestor))
            })
        });
        grants.sort();
        Ok(Self::new(grants))
    }

    pub fn validate(&self, stage_root: &Path) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(policy_error(format!(
                "unsupported write-policy schema version {}",
                self.schema_version
            )));
        }
        self.check_global_invariants()?;
        let stage_root = stage_root.canonicalize().map_err(|error| {
            AutoCageError::io(ErrorKind::Policy, "canonicalize stage root", error)
        })?;
        let normalized = self.normalize()?;
        if normalized.write_grants != self.write_grants {
            return Err(policy_error(
                "write policy is not normalized; duplicate or subsumed grants are forbidden",
            ));
        }
        for grant in &self.write_grants {
            let path = grant_path(grant);
            validate_relative(path)?;
            let target = if path == Path::new(".") {
                stage_root.clone()
            } else {
                stage_root.join(path)
            };
            reject_symlink_components(&stage_root, path)?;
            let meta = std::fs::symlink_metadata(&target).map_err(|error| {
                AutoCageError::io(
                    ErrorKind::Policy,
                    format!("inspect grant {}", path.display()),
                    error,
                )
            })?;
            if meta.file_type().is_symlink() {
                return Err(policy_error(format!(
                    "write grant must not target a symlink: {}",
                    path.display()
                )));
            }
            match grant {
                WriteGrant::FileContents(_) if !meta.is_file() => {
                    return Err(policy_error(format!(
                        "file-content grant must target a regular file: {}",
                        path.display()
                    )));
                }
                WriteGrant::DirectoryTree(_) if !meta.is_dir() => {
                    return Err(policy_error(format!(
                        "directory-tree grant must target a directory: {}",
                        path.display()
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn validate_global_invariants(&self) -> Result<()> {
        self.check_global_invariants()
    }

    /// True only when each candidate grant's complete write authority is
    /// included in at least one grant in the authorized ceiling.
    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool> {
        self.check_global_invariants()?;
        ceiling.check_global_invariants()?;
        for candidate in &self.write_grants {
            validate_relative(grant_path(candidate))?;
            let allowed =
                ceiling
                    .write_grants
                    .iter()
                    .any(|ceiling_grant| match (candidate, ceiling_grant) {
                        (
                            WriteGrant::FileContents(path),
                            WriteGrant::FileContents(allowed_path),
                        ) => path == allowed_path,
                        (
                            WriteGrant::FileContents(path),
                            WriteGrant::DirectoryTree(allowed_path),
                        ) => path_is_same_or_child(path, allowed_path),
                        (
                            WriteGrant::DirectoryTree(path),
                            WriteGrant::DirectoryTree(allowed_path),
                        ) => path_is_same_or_child(path, allowed_path),
                        (WriteGrant::DirectoryTree(_), WriteGrant::FileContents(_)) => false,
                    });
            if !allowed {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn check_global_invariants(&self) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(policy_error("unsupported write-policy schema version"));
        }
        if self.network_access {
            return Err(policy_error(
                "network access is outside the M2 permission ceiling",
            ));
        }
        if !self.disable_nested_userns {
            return Err(policy_error("nested user namespaces must remain disabled"));
        }
        Ok(())
    }
}

pub fn grant_path(grant: &WriteGrant) -> &Path {
    match grant {
        WriteGrant::FileContents(path) | WriteGrant::DirectoryTree(path) => path,
    }
}

pub fn is_directory_grant(grant: &WriteGrant) -> bool {
    matches!(grant, WriteGrant::DirectoryTree(_))
}

pub fn path_is_same_or_child(path: &Path, ancestor: &Path) -> bool {
    path == ancestor
        || (ancestor == Path::new(".") && path != Path::new("."))
        || path.starts_with(ancestor)
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Err(policy_error(format!(
            "absolute write-grant path is forbidden: {}",
            path.display()
        )));
    }
    if path == Path::new(".") {
        return Ok(());
    }
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path.to_str().map_or(true, |value| {
            value.is_empty()
                || value.starts_with('/')
                || value.ends_with('/')
                || value.contains("//")
                || value.split('/').any(|part| part == "." || part == "..")
        })
    {
        return Err(policy_error(format!(
            "write-grant path is not a normalized relative path: {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    if relative == Path::new(".") {
        return Ok(());
    }
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(policy_error("non-normal path component in write grant"));
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            AutoCageError::io(
                ErrorKind::Policy,
                "inspect write-grant path component",
                error,
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(policy_error(format!(
                "write grant traverses a symlink: {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn policy_error(message: impl Into<String>) -> AutoCageError {
    AutoCageError::new(ErrorKind::Policy, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("autocage-policy-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn baseline_is_broad_no_network_and_nested_userns_disabled() {
        let policy = ExecutionPolicy::baseline();
        assert_eq!(
            policy.write_grants,
            vec![WriteGrant::DirectoryTree(PathBuf::from("."))]
        );
        assert!(!policy.network_access);
        assert!(policy.disable_nested_userns);
        assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION);
    }

    #[test]
    fn exact_file_is_subset_of_directory_but_directory_is_not_subset_of_file() {
        let ceiling = ExecutionPolicy::baseline();
        let file = ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("src/a.rs"))]);
        let dir = ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from("src"))]);
        assert!(file.is_subset_of(&ceiling).unwrap());
        assert!(dir.is_subset_of(&ceiling).unwrap());
        assert!(!dir.is_subset_of(&file).unwrap());
    }

    #[test]
    fn normalization_is_deterministic_and_removes_subsumed_grants() {
        let policy = ExecutionPolicy::new(vec![
            WriteGrant::FileContents(PathBuf::from("src/a.rs")),
            WriteGrant::DirectoryTree(PathBuf::from("src")),
            WriteGrant::DirectoryTree(PathBuf::from("src")),
        ]);
        assert_eq!(
            policy.normalize().unwrap().write_grants,
            vec![WriteGrant::DirectoryTree(PathBuf::from("src"))]
        );
    }

    #[test]
    fn rejects_overlapping_noncanonical_serialized_rules() {
        let root = temp_dir();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(root.join("src/a.rs"), "x").unwrap();
        let policy = ExecutionPolicy::new(vec![
            WriteGrant::DirectoryTree(PathBuf::from("src")),
            WriteGrant::FileContents(PathBuf::from("src/a.rs")),
        ]);
        assert!(policy
            .validate(&root)
            .unwrap_err()
            .message
            .contains("not normalized"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_path_traversal_and_symlink_components() {
        let root = temp_dir();
        fs::create_dir(root.join("inside")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("inside", root.join("alias")).unwrap();
        for path in ["../outside", "inside/../inside", "inside//x", "/tmp"] {
            let candidate =
                ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from(path))]);
            assert!(candidate.normalize().is_err(), "accepted {path}");
        }
        #[cfg(unix)]
        {
            let candidate =
                ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from("alias"))]);
            assert!(candidate
                .validate(&root)
                .unwrap_err()
                .message
                .contains("symlink"));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_file_requires_regular_file_and_directory_requires_directory() {
        let root = temp_dir();
        fs::write(root.join("file"), "x").unwrap();
        assert!(
            ExecutionPolicy::new(vec![WriteGrant::FileContents(PathBuf::from("file"))])
                .validate(&root)
                .is_ok()
        );
        assert!(
            ExecutionPolicy::new(vec![WriteGrant::DirectoryTree(PathBuf::from("file"))])
                .validate(&root)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
