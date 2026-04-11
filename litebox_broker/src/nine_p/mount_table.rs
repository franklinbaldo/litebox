// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mount table for mapping guest-relative path prefixes to host directories.
//!
//! When the 9P server walks into a guest path that matches a mount point,
//! the walk redirects into the mounted host directory instead of the
//! server's root directory.

use std::path::{Path, PathBuf};

/// Maps guest-relative path prefixes to host directory paths.
///
/// Mount points are sorted longest-prefix-first so that nested mounts
/// (e.g., `etc` and `etc/app`) resolve correctly.
#[derive(Debug, Clone)]
pub struct MountTable {
    /// Sorted longest-prefix-first: `(guest_prefix, host_path)`.
    mounts: Vec<(PathBuf, PathBuf)>,
}

impl MountTable {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Add a bind mount: guest paths under `guest_prefix` resolve to
    /// `host_path` instead of `root/guest_prefix`.
    ///
    /// `guest_prefix` must be a relative path (no leading `/`).
    /// `host_path` must be an absolute, canonicalized host path.
    pub fn add(&mut self, guest_prefix: PathBuf, host_path: PathBuf) {
        self.mounts.push((guest_prefix, host_path));
        // Sort longest-prefix-first for correct nested mount resolution.
        self.mounts
            .sort_by(|a, b| b.0.components().count().cmp(&a.0.components().count()));
    }

    /// Check if `guest_relative_path` falls under a mount point.
    ///
    /// Returns `Some(host_path)` where `host_path` is the fully resolved
    /// host path for the guest path, or `None` if no mount matches.
    pub fn resolve(&self, guest_relative_path: &Path) -> Option<PathBuf> {
        for (prefix, host_target) in &self.mounts {
            if let Ok(suffix) = guest_relative_path.strip_prefix(prefix) {
                if suffix == Path::new("") {
                    return Some(host_target.clone());
                }
                return Some(host_target.join(suffix));
            }
        }
        None
    }

    /// Return mount points whose parent is `guest_relative_dir`.
    ///
    /// Used by `handle_readdir` to inject mount point entries into
    /// directory listings.
    pub fn children_of(&self, guest_relative_dir: &Path) -> Vec<&Path> {
        self.mounts
            .iter()
            .filter_map(|(prefix, _)| {
                let parent = prefix.parent()?;
                if parent == guest_relative_dir {
                    // Return just the final component name as a Path
                    Some(prefix.file_name().map(Path::new)?)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Check if a host path is under any mount target.
    pub fn is_under_mount(&self, host_path: &Path) -> bool {
        self.mounts
            .iter()
            .any(|(_, target)| host_path.starts_with(target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_exact_match() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt/data"), PathBuf::from("/host/data"));

        let result = table.resolve(Path::new("mnt/data"));
        assert_eq!(result, Some(PathBuf::from("/host/data")));
    }

    #[test]
    fn resolve_subpath() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt/data"), PathBuf::from("/host/data"));

        let result = table.resolve(Path::new("mnt/data/file.txt"));
        assert_eq!(result, Some(PathBuf::from("/host/data/file.txt")));
    }

    #[test]
    fn resolve_no_match() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt/data"), PathBuf::from("/host/data"));

        let result = table.resolve(Path::new("other/path"));
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_nested_mounts_longer_prefix_wins() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("etc"), PathBuf::from("/host/etc"));
        table.add(PathBuf::from("etc/app"), PathBuf::from("/host/app-etc"));

        // The longer prefix "etc/app" should match first
        let result = table.resolve(Path::new("etc/app/config.toml"));
        assert_eq!(result, Some(PathBuf::from("/host/app-etc/config.toml")));

        // Plain "etc" still works for non-app paths
        let result = table.resolve(Path::new("etc/hosts"));
        assert_eq!(result, Some(PathBuf::from("/host/etc/hosts")));
    }

    #[test]
    fn children_of_returns_mount_names() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt/data"), PathBuf::from("/host/data"));
        table.add(PathBuf::from("mnt/config"), PathBuf::from("/host/config"));
        table.add(PathBuf::from("other/stuff"), PathBuf::from("/host/stuff"));

        let children = table.children_of(Path::new("mnt"));
        let mut names: Vec<&str> = children.iter().map(|p| p.to_str().unwrap()).collect();
        names.sort();
        assert_eq!(names, vec!["config", "data"]);
    }

    #[test]
    fn children_of_root() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt"), PathBuf::from("/host/mnt"));

        // Parent of "mnt" is "" (empty path)
        let children = table.children_of(Path::new(""));
        assert_eq!(children.len(), 1);
        assert_eq!(children[0], Path::new("mnt"));
    }

    #[test]
    fn is_under_mount_checks_host_paths() {
        let mut table = MountTable::new();
        table.add(PathBuf::from("mnt/data"), PathBuf::from("/host/data"));

        assert!(table.is_under_mount(Path::new("/host/data")));
        assert!(table.is_under_mount(Path::new("/host/data/subdir/file.txt")));
        assert!(!table.is_under_mount(Path::new("/other/path")));
        assert!(!table.is_under_mount(Path::new("/host/data-other")));
    }

    #[test]
    fn empty_table() {
        let table = MountTable::new();
        assert!(table.is_empty());
        assert_eq!(table.resolve(Path::new("any/path")), None);
        assert!(table.children_of(Path::new("any")).is_empty());
        assert!(!table.is_under_mount(Path::new("/any/path")));
    }
}
