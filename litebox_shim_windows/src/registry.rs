// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VFS-backed registry implementation.
//!
//! Maps Windows NT registry paths to a directory tree in the VFS under
//! `/__registry/`.  Registry keys are directories, and values are files
//! in a `__values/` subdirectory of each key directory.
//!
//! ## VFS Layout
//!
//! ```text
//! /__registry/machine/system/currentcontrolset/services/winsock2/parameters/
//! /__registry/machine/system/.../parameters/__values/winsock_registry_version
//! ```
//!
//! Each value file is encoded as:
//! - bytes `0..4`: little-endian `u32` registry type (REG_SZ=1, REG_BINARY=3, …)
//! - bytes `4..`:  raw value data
//!
//! ## Path Mapping
//!
//! | NT Path                         | VFS Path                    |
//! |---------------------------------|-----------------------------|
//! | `\Registry\Machine\Foo\Bar`     | `/__registry/machine/foo/bar` |
//! | `\Registry\User\.DEFAULT\Foo`   | `/__registry/user/.default/foo` |
//! | `\Registry\User\S-1-5-...\Foo`  | `/__registry/user/.default/foo` |

use alloc::string::String;
use alloc::vec::Vec;

/// Registry VFS root prefix (no trailing slash).
const REGISTRY_VFS_ROOT: &str = "/__registry";

/// Subdirectory within each key directory that holds value files.
const VALUES_DIR: &str = "__values";

/// Filename for the unnamed default value.
const DEFAULT_VALUE_NAME: &str = "__default";

/// Translate an NT registry key path to a VFS directory path.
///
/// Returns `None` if the path doesn't start with `\Registry\`.
///
/// Examples:
/// - `\Registry\Machine\System\Foo` → `/__registry/machine/system/foo`
/// - `\REGISTRY\USER\.DEFAULT\Bar`  → `/__registry/user/.default/bar`
/// - `\Registry\User\S-1-5-18\Bar`  → `/__registry/user/.default/bar`
pub fn registry_key_to_vfs_path(nt_path: &str) -> Option<String> {
    // Case-insensitive prefix match for "\Registry\" or "\REGISTRY\"
    let lower = nt_path.to_ascii_lowercase();
    let rest = lower.strip_prefix("\\registry\\")?;

    // Map the hive root and remaining subpath
    let vfs_rest = if let Some(suffix) = rest.strip_prefix("machine") {
        // Require end-of-string or '\' after "machine" to avoid matching
        // "machinery" etc.
        if !suffix.is_empty() && !suffix.starts_with('\\') {
            return None;
        }
        let tail = suffix.strip_prefix('\\').unwrap_or("");
        if tail.is_empty() {
            String::from("machine")
        } else {
            alloc::format!("machine/{}", tail.replace('\\', "/"))
        }
    } else if let Some(suffix) = rest.strip_prefix("user") {
        if !suffix.is_empty() && !suffix.starts_with('\\') {
            return None;
        }
        let tail = suffix.strip_prefix('\\').unwrap_or("");
        if tail.is_empty() {
            String::from("user")
        } else {
            // Map any user SID to .default for now (single-user sandbox)
            let (first_component, remaining) = match tail.find('\\') {
                Some(pos) => (&tail[..pos], &tail[pos + 1..]),
                None => (tail, ""),
            };
            let mapped_user = if first_component == ".default" || first_component.starts_with("s-")
            {
                ".default"
            } else {
                first_component
            };
            if remaining.is_empty() {
                alloc::format!("user/{mapped_user}")
            } else {
                alloc::format!("user/{mapped_user}/{}", remaining.replace('\\', "/"))
            }
        }
    } else {
        // Unknown hive — pass through lowercased
        rest.replace('\\', "/")
    };

    Some(alloc::format!("{REGISTRY_VFS_ROOT}/{vfs_rest}"))
}

/// Build the VFS path for a registry value file.
///
/// The value file lives at `<key_vfs_path>/__values/<value_name_lower>`.
/// An empty value name maps to `__default`.
pub fn registry_value_to_vfs_path(key_vfs_path: &str, value_name: &str) -> String {
    let name = if value_name.is_empty() {
        String::from(DEFAULT_VALUE_NAME)
    } else {
        value_name.to_ascii_lowercase()
    };
    alloc::format!("{key_vfs_path}/{VALUES_DIR}/{name}")
}

/// Read a registry value from the VFS.
///
/// Returns `Some((reg_type, data))` where `data` is the raw value bytes
/// (without the 4-byte type prefix), or `None` if not found.
pub fn read_registry_value<FS: litebox::fs::FileSystem>(
    fs: &FS,
    key_vfs_path: &str,
    value_name: &str,
) -> Option<(u32, Vec<u8>)> {
    let vfs_path = registry_value_to_vfs_path(key_vfs_path, value_name);

    let fd = fs
        .open(
            &vfs_path,
            litebox::fs::OFlags::RDONLY,
            litebox::fs::Mode::RUSR,
        )
        .ok()?;

    let size = match fs.fd_file_status(&fd).map(|s| s.size as usize) {
        Ok(s) => s,
        Err(_) => {
            let _ = fs.close(&fd);
            return None;
        }
    };
    if size < 4 {
        let _ = fs.close(&fd);
        return None;
    }

    let mut buf = alloc::vec![0u8; size];
    let bytes_read = fs.read(&fd, &mut buf, None).unwrap_or(0);
    let _ = fs.close(&fd);

    if bytes_read < 4 {
        return None;
    }
    buf.truncate(bytes_read);

    let reg_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let data = buf[4..].to_vec();
    Some((reg_type, data))
}

/// Check whether a registry key exists in the VFS (i.e. the directory exists).
pub fn registry_key_exists<FS: litebox::fs::FileSystem>(fs: &FS, key_vfs_path: &str) -> bool {
    // A key exists if its directory or its __values/ subdirectory exists.
    fs.file_status(key_vfs_path)
        .map(|s| s.file_type == litebox::fs::FileType::Directory)
        .unwrap_or(false)
}

/// Enumerate subkeys of a registry key (directory listing minus `__values`).
///
/// Returns subkey names (not full paths) in whatever order the VFS provides.
pub fn enumerate_subkeys<FS: litebox::fs::FileSystem>(fs: &FS, key_vfs_path: &str) -> Vec<String> {
    let mut subkeys = Vec::new();

    let fd = match fs.open(
        key_vfs_path,
        litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
        litebox::fs::Mode::RUSR,
    ) {
        Ok(fd) => fd,
        Err(_) => return subkeys,
    };

    if let Ok(entries) = fs.read_dir(&fd) {
        for entry in entries {
            let name = &entry.name;
            if name != VALUES_DIR && name != "." && name != ".." {
                if entry.file_type == litebox::fs::FileType::Directory {
                    subkeys.push(name.clone());
                }
            }
        }
    }

    let _ = fs.close(&fd);
    subkeys
}

/// Enumerate value names under a registry key.
///
/// Returns value names (lowercased). The `__default` sentinel is mapped
/// back to an empty string for the caller.
pub fn enumerate_values<FS: litebox::fs::FileSystem>(fs: &FS, key_vfs_path: &str) -> Vec<String> {
    let mut values = Vec::new();
    let values_dir = alloc::format!("{key_vfs_path}/{VALUES_DIR}");

    let fd = match fs.open(
        &values_dir,
        litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
        litebox::fs::Mode::RUSR,
    ) {
        Ok(fd) => fd,
        Err(_) => return values,
    };

    if let Ok(entries) = fs.read_dir(&fd) {
        for entry in entries {
            let name = &entry.name;
            if name == "." || name == ".." {
                continue;
            }
            if name == DEFAULT_VALUE_NAME {
                values.push(String::new());
            } else {
                values.push(name.clone());
            }
        }
    }

    let _ = fs.close(&fd);
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_path_translation() {
        assert_eq!(
            registry_key_to_vfs_path(r"\Registry\Machine\System\Foo"),
            Some(String::from("/__registry/machine/system/foo"))
        );
        assert_eq!(
            registry_key_to_vfs_path(r"\REGISTRY\MACHINE\System\Bar"),
            Some(String::from("/__registry/machine/system/bar"))
        );
        assert_eq!(
            registry_key_to_vfs_path(r"\Registry\User\.DEFAULT\Baz"),
            Some(String::from("/__registry/user/.default/baz"))
        );
        assert_eq!(
            registry_key_to_vfs_path(r"\Registry\User\S-1-5-18\Baz"),
            Some(String::from("/__registry/user/.default/baz"))
        );
        assert_eq!(
            registry_key_to_vfs_path(r"\Registry\Machine"),
            Some(String::from("/__registry/machine"))
        );
        assert_eq!(registry_key_to_vfs_path(r"\NotRegistry\Foo"), None);
        // Hive boundary: "Machinery" should NOT match "Machine"
        assert_eq!(registry_key_to_vfs_path(r"\Registry\Machinery\Foo"), None);
        assert_eq!(registry_key_to_vfs_path(r"\Registry\Userland\Foo"), None);
    }

    #[test]
    fn test_value_path() {
        assert_eq!(
            registry_value_to_vfs_path("/__registry/machine/foo", "Bar"),
            "/__registry/machine/foo/__values/bar"
        );
        assert_eq!(
            registry_value_to_vfs_path("/__registry/machine/foo", ""),
            "/__registry/machine/foo/__values/__default"
        );
    }
}
