// Build orchestrator — processes Dockerfile instructions to produce an OCI bundle.
//
// Pulls the base image, runs commands in a sandbox, copies files, accumulates
// metadata (ENV, WORKDIR, ENTRYPOINT, CMD), and writes the final config.json.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::dockerfile::Instruction;
use crate::spec_gen::{ImageMetadata, write_config_json};

/// Build an OCI bundle from a parsed Dockerfile.
///
/// Processes instructions in order: pulls the base image, runs commands,
/// copies/adds files, accumulates env/workdir/entrypoint/cmd metadata,
/// and writes `config.json` to `output_dir`.
pub fn build(instructions: &[Instruction], context_dir: &Path, output_dir: &Path) -> Result<()> {
    // Validate: first instruction must be FROM.
    if instructions.is_empty() {
        bail!("Dockerfile has no instructions");
    }
    if !matches!(&instructions[0], Instruction::From { .. }) {
        bail!("first Dockerfile instruction must be FROM");
    }

    // Reject multiple FROM instructions (no multi-stage builds).
    let from_count = instructions
        .iter()
        .filter(|i| matches!(i, Instruction::From { .. }))
        .count();
    if from_count > 1 {
        bail!("multiple FROM instructions are not supported (no multi-stage builds)");
    }

    let rootfs_dir = output_dir.join("rootfs");
    fs::create_dir_all(&rootfs_dir)
        .with_context(|| format!("failed to create rootfs dir: {}", rootfs_dir.display()))?;

    let mut metadata = ImageMetadata::default();

    for instruction in instructions {
        match instruction {
            Instruction::From { image } => {
                eprintln!("[BUILD] FROM {image}");
                pull_and_extract_base(image, &rootfs_dir, &mut metadata)?;
            }
            Instruction::Run { command } => {
                eprintln!("[BUILD] RUN {command}");
                let shell_cmd = vec!["/bin/sh".to_string(), "-c".to_string(), command.clone()];
                let working_dir = metadata.working_dir.as_deref();
                let exit_code = crate::runner::run_build_step(
                    &rootfs_dir,
                    &shell_cmd,
                    &metadata.env,
                    working_dir,
                )?;
                if exit_code != 0 {
                    bail!("RUN command failed with exit code {exit_code}: {command}");
                }
            }
            Instruction::Copy { sources, dest } => {
                eprintln!("[BUILD] COPY {} {dest}", sources.join(" "));
                copy_files(context_dir, sources, dest, &rootfs_dir, &metadata)?;
            }
            Instruction::Add { sources, dest } => {
                eprintln!("[BUILD] ADD {} {dest}", sources.join(" "));
                add_files(context_dir, sources, dest, &rootfs_dir, &metadata)?;
            }
            Instruction::Env { key, value } => {
                eprintln!("[BUILD] ENV {key}={value}");
                let env_entry = format!("{key}={value}");
                // Remove any existing entry for this key, then add the new one.
                metadata.env.retain(|e| !e.starts_with(&format!("{key}=")));
                metadata.env.push(env_entry);
            }
            Instruction::Workdir { path } => {
                eprintln!("[BUILD] WORKDIR {path}");
                metadata.working_dir = Some(path.clone());
                // Create the directory in the rootfs.
                let resolved = resolve_dest(&rootfs_dir, path, &metadata);
                fs::create_dir_all(&resolved)
                    .with_context(|| format!("failed to create WORKDIR: {}", resolved.display()))?;
            }
            Instruction::Entrypoint { exec } => {
                eprintln!("[BUILD] ENTRYPOINT {exec:?}");
                metadata.entrypoint = Some(exec.clone());
            }
            Instruction::Cmd { exec } => {
                eprintln!("[BUILD] CMD {exec:?}");
                metadata.cmd = Some(exec.clone());
            }
        }
    }

    // Write config.json from accumulated metadata.
    eprintln!("[BUILD] Writing config.json");
    write_config_json(output_dir, &metadata)?;

    eprintln!("[BUILD] Build complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: validate source path is within build context
// ---------------------------------------------------------------------------

/// Ensure that `src_path` (after joining with context_dir) resolves to a
/// location inside `context_dir`. Prevents `../../../etc/shadow`-style path
/// traversal attacks in COPY/ADD source arguments.
fn validate_source_in_context(context_dir: &Path, source: &str) -> Result<PathBuf> {
    let src_path = context_dir.join(source);
    let canonical_ctx = context_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize context dir: {}",
            context_dir.display()
        )
    })?;
    let canonical_src = src_path.canonicalize().with_context(|| {
        format!(
            "source does not exist or cannot be resolved: {} (in context {})",
            source,
            context_dir.display()
        )
    })?;
    ensure!(
        canonical_src.starts_with(&canonical_ctx),
        "source path '{}' escapes build context (resolves to {})",
        source,
        canonical_src.display()
    );
    Ok(canonical_src)
}

// ---------------------------------------------------------------------------
// Helper: pull base image
// ---------------------------------------------------------------------------

/// Pull a base image and extract its rootfs to `rootfs_dir`.
///
/// Inherits the base image's ENV, WORKDIR, ENTRYPOINT, and CMD into `metadata`.
#[cfg(target_arch = "x86_64")]
fn pull_and_extract_base(
    image: &str,
    rootfs_dir: &Path,
    metadata: &mut ImageMetadata,
) -> Result<()> {
    // FROM scratch is a special case: empty rootfs, no image to pull.
    if image == "scratch" {
        return Ok(());
    }

    let extracted = litebox_packager::oci::pull_and_extract(image, true)
        .with_context(|| format!("failed to pull base image: {image}"))?;

    // Copy the extracted rootfs into our output rootfs directory.
    // materialize_symlinks turns file symlinks into copies but replaces
    // directory symlinks (e.g. /lib64 -> usr/lib64) with empty directories.
    // We must restore those as real symlinks so the guest can resolve paths
    // like /lib64/ld-linux-x86-64.so.2.
    copy_dir_recursive(&extracted.rootfs_path, rootfs_dir)
        .context("failed to copy base image rootfs")?;

    // Restore directory symlinks that materialize_symlinks replaced with
    // empty placeholder directories.
    restore_directory_symlinks(&extracted.symlinks, rootfs_dir)?;

    // Ensure /etc/resolv.conf exists with working DNS servers so that RUN
    // steps can resolve hostnames (apt-get, curl, etc.).  The broker's
    // network proxy relays all traffic through the host, so public DNS
    // servers like 8.8.8.8 and 1.1.1.1 work correctly.
    ensure_resolv_conf(rootfs_dir)?;

    // Inherit base image config into metadata.
    let config = &extracted.config;
    if let Some(ref env) = config.env {
        for entry in env {
            // Only add if not already overridden.
            if let Some(key) = entry.split('=').next()
                && !metadata
                    .env
                    .iter()
                    .any(|e| e.starts_with(&format!("{key}=")))
            {
                metadata.env.push(entry.clone());
            }
        }
    }
    if let Some(ref working_dir) = config.working_dir
        && metadata.working_dir.is_none()
    {
        metadata.working_dir = Some(working_dir.clone());
    }
    if let Some(ref entrypoint) = config.entrypoint
        && metadata.entrypoint.is_none()
    {
        metadata.entrypoint = Some(entrypoint.clone());
    }
    if let Some(ref cmd) = config.cmd
        && metadata.cmd.is_none()
    {
        metadata.cmd = Some(cmd.clone());
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn pull_and_extract_base(
    image: &str,
    _rootfs_dir: &Path,
    _metadata: &mut ImageMetadata,
) -> Result<()> {
    bail!("pulling base images is only supported on x86_64 (requested: {image})");
}

// ---------------------------------------------------------------------------
// Helper: ensure /etc/resolv.conf for DNS in build steps
// ---------------------------------------------------------------------------

/// Ensure the rootfs contains a working `/etc/resolv.conf`.
///
/// Many container base images ship without one, or with a Docker-internal
/// resolver (127.0.0.11) that won't work in our sandbox.  We write public
/// DNS servers that the broker's network proxy can relay through the host.
/// If the file already exists and looks valid (contains a `nameserver` line
/// that isn't localhost), we leave it alone.
fn ensure_resolv_conf(rootfs_dir: &Path) -> Result<()> {
    let etc_dir = rootfs_dir.join("etc");
    let resolv_path = etc_dir.join("resolv.conf");

    // If it already exists and contains a non-localhost nameserver, keep it.
    if resolv_path.exists()
        && let Ok(content) = fs::read_to_string(&resolv_path)
    {
        let has_working_ns = content.lines().any(|line| {
            let line = line.trim();
            line.starts_with("nameserver") && !line.contains("127.0.0") && !line.contains("::1")
        });
        if has_working_ns {
            return Ok(());
        }
    }

    // Create /etc if it doesn't exist (FROM scratch).
    fs::create_dir_all(&etc_dir).context("failed to create /etc in rootfs")?;

    // Write a minimal resolv.conf with public DNS.
    fs::write(
        &resolv_path,
        "# Generated by litebox-oci build\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n",
    )
    .context("failed to write /etc/resolv.conf in rootfs")?;

    eprintln!("[BUILD]   wrote /etc/resolv.conf (DNS: 8.8.8.8, 1.1.1.1)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: resolve destination path
// ---------------------------------------------------------------------------

/// Resolve a destination path relative to WORKDIR and rootfs.
///
/// If `dest` starts with `/`, it is absolute (relative to rootfs).
/// Otherwise it is relative to the current WORKDIR (defaulting to `/`).
fn resolve_dest(rootfs_dir: &Path, dest: &str, metadata: &ImageMetadata) -> PathBuf {
    if dest.starts_with('/') {
        // Absolute path: strip the leading / and join with rootfs.
        let stripped = dest.strip_prefix('/').unwrap_or(dest);
        rootfs_dir.join(stripped)
    } else {
        // Relative to WORKDIR.
        let workdir = metadata.working_dir.as_deref().unwrap_or("/");
        let stripped = workdir.strip_prefix('/').unwrap_or(workdir);
        rootfs_dir.join(stripped).join(dest)
    }
}

// ---------------------------------------------------------------------------
// Helper: COPY files
// ---------------------------------------------------------------------------

/// Copy files from build context to rootfs (for COPY instruction).
fn copy_files(
    context_dir: &Path,
    sources: &[String],
    dest: &str,
    rootfs_dir: &Path,
    metadata: &ImageMetadata,
) -> Result<()> {
    let resolved_dest = resolve_dest(rootfs_dir, dest, metadata);

    // If dest ends with '/' or there are multiple sources, treat dest as a directory.
    let dest_is_dir = dest.ends_with('/') || sources.len() > 1;

    if dest_is_dir {
        fs::create_dir_all(&resolved_dest).with_context(|| {
            format!(
                "failed to create destination directory: {}",
                resolved_dest.display()
            )
        })?;
    }

    for source in sources {
        let src_path = validate_source_in_context(context_dir, source)?;
        let target = if dest_is_dir {
            let filename = src_path
                .file_name()
                .context("COPY source has no filename")?;
            resolved_dest.join(filename)
        } else {
            // Ensure parent directory exists.
            if let Some(parent) = resolved_dest.parent() {
                fs::create_dir_all(parent)?;
            }
            resolved_dest.clone()
        };

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &target)?;
        } else {
            fs::copy(&src_path, &target).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    src_path.display(),
                    target.display()
                )
            })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: ADD files (with tar auto-extraction)
// ---------------------------------------------------------------------------

/// Add files from build context to rootfs with tar auto-extraction (for ADD instruction).
fn add_files(
    context_dir: &Path,
    sources: &[String],
    dest: &str,
    rootfs_dir: &Path,
    metadata: &ImageMetadata,
) -> Result<()> {
    let resolved_dest = resolve_dest(rootfs_dir, dest, metadata);

    let dest_is_dir = dest.ends_with('/') || sources.len() > 1;

    if dest_is_dir {
        fs::create_dir_all(&resolved_dest).with_context(|| {
            format!(
                "failed to create destination directory: {}",
                resolved_dest.display()
            )
        })?;
    }

    for source in sources {
        let src_path = validate_source_in_context(context_dir, source)?;

        // Check if the source is a tar archive that should be auto-extracted.
        if is_tar_archive(source) && src_path.is_file() {
            fs::create_dir_all(&resolved_dest)?;
            extract_tar(&src_path, &resolved_dest)
                .with_context(|| format!("failed to extract archive: {}", src_path.display()))?;
        } else {
            // Non-archive: same as COPY.
            let target = if dest_is_dir {
                let filename = src_path.file_name().context("ADD source has no filename")?;
                resolved_dest.join(filename)
            } else {
                if let Some(parent) = resolved_dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                resolved_dest.clone()
            };

            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &target)?;
            } else {
                fs::copy(&src_path, &target).with_context(|| {
                    format!(
                        "failed to copy {} to {}",
                        src_path.display(),
                        target.display()
                    )
                })?;
            }
        }
    }

    Ok(())
}

/// Check if a filename looks like a tar archive.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_tar_archive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".tar") || lower.ends_with(".tar.gz") || lower.ends_with(".tgz")
}

/// Extract a tar archive (possibly gzipped) to the given directory.
fn extract_tar(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("failed to open archive: {}", archive_path.display()))?;

    let name = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let lower = name.to_ascii_lowercase();

    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(dest_dir).with_context(|| {
            format!("failed to extract gzipped tar: {}", archive_path.display())
        })?;
    } else {
        let mut archive = tar::Archive::new(file);
        archive
            .unpack(dest_dir)
            .with_context(|| format!("failed to extract tar: {}", archive_path.display()))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: recursive directory copy
// ---------------------------------------------------------------------------

/// Recursively copy a directory tree, preserving symlinks and permissions.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)
            .with_context(|| format!("failed to create directory: {}", dst.display()))?;
    }

    for entry in
        fs::read_dir(src).with_context(|| format!("failed to read directory: {}", src.display()))?
    {
        let entry = entry?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            // Preserve symlinks.
            let target = fs::read_link(&src_path)
                .with_context(|| format!("failed to read symlink: {}", src_path.display()))?;
            // Remove existing file/symlink at destination.
            let _ = fs::remove_file(&dst_path);
            std::os::unix::fs::symlink(&target, &dst_path).with_context(|| {
                format!(
                    "failed to create symlink {} -> {}",
                    dst_path.display(),
                    target.display()
                )
            })?;
        } else if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            // Regular file: copy content and preserve permissions.
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    src_path.display(),
                    dst_path.display()
                )
            })?;
            // Preserve permissions.
            let src_meta = fs::metadata(&src_path)?;
            let permissions = fs::Permissions::from_mode(src_meta.permissions().mode());
            fs::set_permissions(&dst_path, permissions).ok();
        }
    }

    // Preserve directory permissions.
    let src_meta = fs::metadata(src)?;
    let permissions = fs::Permissions::from_mode(src_meta.permissions().mode());
    fs::set_permissions(dst, permissions).ok();

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: restore directory symlinks after copying base image
// ---------------------------------------------------------------------------

/// Restore directory symlinks that `materialize_symlinks` replaced with empty
/// placeholder directories.
///
/// Debian-style images use top-level symlinks like `/lib64 -> usr/lib64`,
/// `/bin -> usr/bin`, etc.  The packager's `materialize_symlinks` replaces
/// these with empty directories (for cross-platform compatibility during
/// packaging).  For a writable rootfs we need real symlinks so the guest
/// dynamic linker can resolve `/lib64/ld-linux-x86-64.so.2`.
#[cfg(target_arch = "x86_64")]
fn restore_directory_symlinks(
    symlinks: &[litebox_packager::oci::DeferredSymlink],
    rootfs_dir: &Path,
) -> Result<()> {
    use std::collections::HashMap;

    // Build a symlink map to resolve chains.
    let symlink_map: HashMap<&Path, &Path> = symlinks
        .iter()
        .map(|s| (s.rel_path.as_path(), s.link_target.as_path()))
        .collect();

    for sym in symlinks {
        let host_path = rootfs_dir.join(&sym.rel_path);

        // Only fix directory symlinks: the host_path was created as an empty
        // directory by materialize_symlinks.  Skip file symlinks (already
        // materialized as copies) and non-existent paths.
        if !host_path.is_dir() {
            continue;
        }

        // Resolve the target to see if it points to a real directory in rootfs.
        let target = &sym.link_target;
        let resolved = resolve_symlink_target(target, rootfs_dir, &symlink_map, 16);
        let resolved_host = if let Some(p) = &resolved {
            p.clone()
        } else {
            // Try absolute target (e.g. /usr/bin -> rootfs/usr/bin).
            let abs_stripped = target
                .to_str()
                .and_then(|s| s.strip_prefix('/'))
                .unwrap_or_else(|| target.to_str().unwrap_or(""));
            rootfs_dir.join(abs_stripped)
        };

        if !resolved_host.is_dir() {
            continue;
        }

        // Check the directory is empty (placeholder) or contains nothing
        // meaningful that wasn't already under the target.
        let is_empty = fs::read_dir(&host_path)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);

        if is_empty {
            // Replace empty directory with a symlink.
            fs::remove_dir(&host_path).with_context(|| {
                format!("failed to remove placeholder dir: {}", host_path.display())
            })?;
            std::os::unix::fs::symlink(target, &host_path).with_context(|| {
                format!(
                    "failed to create directory symlink {} -> {}",
                    host_path.display(),
                    target.display()
                )
            })?;
            eprintln!(
                "[BUILD]   restored symlink: {} -> {}",
                sym.rel_path.display(),
                target.display()
            );
        }
    }

    Ok(())
}

/// Resolve a symlink target path within the rootfs, following chains.
#[cfg(target_arch = "x86_64")]
fn resolve_symlink_target(
    target: &Path,
    rootfs_dir: &Path,
    symlink_map: &std::collections::HashMap<&Path, &Path>,
    max_depth: u32,
) -> Option<PathBuf> {
    let target_str = target.to_str()?;
    // Strip leading / for rootfs-relative lookup.
    let rel = target_str.strip_prefix('/').unwrap_or(target_str);
    let mut current = PathBuf::from(rel);

    for _ in 0..max_depth {
        let host = rootfs_dir.join(&current);
        if host.exists() {
            return Some(host);
        }
        // Check if current is itself a symlink in the map.
        if let Some(&next_target) = symlink_map.get(current.as_path()) {
            let next_str = next_target.to_str()?;
            let next_rel = next_str.strip_prefix('/').unwrap_or(next_str);
            current = PathBuf::from(next_rel);
        } else {
            break;
        }
    }

    let host = rootfs_dir.join(&current);
    if host.exists() { Some(host) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dest_absolute_path() {
        let rootfs = Path::new("/tmp/rootfs");
        let metadata = ImageMetadata::default();
        let result = resolve_dest(rootfs, "/app/data", &metadata);
        assert_eq!(result, PathBuf::from("/tmp/rootfs/app/data"));
    }

    #[test]
    fn resolve_dest_relative_with_workdir() {
        let rootfs = Path::new("/tmp/rootfs");
        let metadata = ImageMetadata {
            working_dir: Some("/app".to_string()),
            ..Default::default()
        };
        let result = resolve_dest(rootfs, "data", &metadata);
        assert_eq!(result, PathBuf::from("/tmp/rootfs/app/data"));
    }

    #[test]
    fn resolve_dest_relative_default_workdir() {
        let rootfs = Path::new("/tmp/rootfs");
        let metadata = ImageMetadata::default();
        let result = resolve_dest(rootfs, "data", &metadata);
        assert_eq!(result, PathBuf::from("/tmp/rootfs/data"));
    }

    #[test]
    fn is_tar_archive_detects_extensions() {
        assert!(is_tar_archive("file.tar"));
        assert!(is_tar_archive("file.tar.gz"));
        assert!(is_tar_archive("file.tgz"));
        assert!(is_tar_archive("FILE.TAR.GZ"));
        assert!(!is_tar_archive("file.txt"));
        assert!(!is_tar_archive("file.zip"));
    }

    #[test]
    fn copy_dir_recursive_preserves_structure() {
        let src_dir = tempfile::tempdir().unwrap();
        let dst_dir = tempfile::tempdir().unwrap();

        // Create source structure: file, subdirectory, symlink.
        fs::write(src_dir.path().join("hello.txt"), "hello").unwrap();
        fs::create_dir(src_dir.path().join("subdir")).unwrap();
        fs::write(src_dir.path().join("subdir/nested.txt"), "nested").unwrap();
        std::os::unix::fs::symlink("hello.txt", src_dir.path().join("link.txt")).unwrap();

        let target = dst_dir.path().join("output");
        copy_dir_recursive(src_dir.path(), &target).unwrap();

        assert!(target.join("hello.txt").exists());
        assert_eq!(
            fs::read_to_string(target.join("hello.txt")).unwrap(),
            "hello"
        );
        assert!(target.join("subdir/nested.txt").exists());
        assert_eq!(
            fs::read_to_string(target.join("subdir/nested.txt")).unwrap(),
            "nested"
        );
        // Symlink should exist and point to the right target.
        let link = fs::read_link(target.join("link.txt")).unwrap();
        assert_eq!(link, PathBuf::from("hello.txt"));
    }

    #[test]
    fn copy_files_single_file() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        fs::write(context.path().join("app.py"), "print('hi')").unwrap();

        let metadata = ImageMetadata {
            working_dir: Some("/app".to_string()),
            ..Default::default()
        };

        copy_files(
            context.path(),
            &["app.py".to_string()],
            "/app/app.py",
            rootfs.path(),
            &metadata,
        )
        .unwrap();

        let dest = rootfs.path().join("app/app.py");
        assert!(dest.exists());
        assert_eq!(fs::read_to_string(dest).unwrap(), "print('hi')");
    }

    #[test]
    fn copy_files_to_directory() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        fs::write(context.path().join("a.txt"), "a").unwrap();
        fs::write(context.path().join("b.txt"), "b").unwrap();

        let metadata = ImageMetadata::default();

        copy_files(
            context.path(),
            &["a.txt".to_string(), "b.txt".to_string()],
            "/dest/",
            rootfs.path(),
            &metadata,
        )
        .unwrap();

        assert!(rootfs.path().join("dest/a.txt").exists());
        assert!(rootfs.path().join("dest/b.txt").exists());
    }

    #[test]
    fn add_files_extracts_tar() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        // Create a small tar archive in the context.
        let tar_path = context.path().join("archive.tar");
        {
            let file = fs::File::create(&tar_path).unwrap();
            let mut builder = tar::Builder::new(file);
            let data = b"hello from tar";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "extracted.txt", &data[..])
                .unwrap();
            builder.finish().unwrap();
        }

        let metadata = ImageMetadata::default();

        add_files(
            context.path(),
            &["archive.tar".to_string()],
            "/dest/",
            rootfs.path(),
            &metadata,
        )
        .unwrap();

        let extracted = rootfs.path().join("dest/extracted.txt");
        assert!(extracted.exists(), "extracted file should exist");
        assert_eq!(fs::read_to_string(extracted).unwrap(), "hello from tar");
    }

    #[test]
    fn add_files_extracts_tar_gz() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        // Create a .tar.gz archive.
        let tgz_path = context.path().join("archive.tar.gz");
        {
            let file = fs::File::create(&tgz_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let data = b"gzipped content";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "gz_file.txt", &data[..])
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }

        let metadata = ImageMetadata::default();

        add_files(
            context.path(),
            &["archive.tar.gz".to_string()],
            "/dest/",
            rootfs.path(),
            &metadata,
        )
        .unwrap();

        let extracted = rootfs.path().join("dest/gz_file.txt");
        assert!(extracted.exists(), "gzipped extracted file should exist");
        assert_eq!(fs::read_to_string(extracted).unwrap(), "gzipped content");
    }

    #[test]
    fn build_rejects_empty_instructions() {
        let context = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let result = build(&[], context.path(), output.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no instructions"));
    }

    #[test]
    fn build_rejects_missing_from() {
        let context = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let instructions = vec![Instruction::Run {
            command: "echo hi".to_string(),
        }];
        let result = build(&instructions, context.path(), output.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be FROM"));
    }

    #[test]
    fn build_rejects_multiple_from() {
        let context = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let instructions = vec![
            Instruction::From {
                image: "alpine".to_string(),
            },
            Instruction::From {
                image: "ubuntu".to_string(),
            },
        ];
        let result = build(&instructions, context.path(), output.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("multiple FROM"));
    }

    #[test]
    fn copy_files_rejects_path_traversal() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        // Create a file inside context so the directory is valid.
        fs::write(context.path().join("legit.txt"), "ok").unwrap();

        let metadata = ImageMetadata::default();

        // Attempt to COPY a source that escapes the build context.
        let result = copy_files(
            context.path(),
            &["../../../etc/passwd".to_string()],
            "/app/",
            rootfs.path(),
            &metadata,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("escapes build context") || err.contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn add_files_rejects_path_traversal() {
        let context = tempfile::tempdir().unwrap();
        let rootfs = tempfile::tempdir().unwrap();

        fs::write(context.path().join("legit.txt"), "ok").unwrap();

        let metadata = ImageMetadata::default();

        let result = add_files(
            context.path(),
            &["../../../etc/passwd".to_string()],
            "/app/",
            rootfs.path(),
            &metadata,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("escapes build context") || err.contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_source_in_context_allows_valid_paths() {
        let context = tempfile::tempdir().unwrap();
        fs::write(context.path().join("hello.txt"), "hi").unwrap();
        fs::create_dir(context.path().join("subdir")).unwrap();
        fs::write(context.path().join("subdir/nested.txt"), "nested").unwrap();

        // Direct file
        assert!(validate_source_in_context(context.path(), "hello.txt").is_ok());
        // Nested file
        assert!(validate_source_in_context(context.path(), "subdir/nested.txt").is_ok());
        // Directory
        assert!(validate_source_in_context(context.path(), "subdir").is_ok());
    }

    #[test]
    fn validate_source_in_context_rejects_traversal() {
        let context = tempfile::tempdir().unwrap();
        fs::write(context.path().join("legit.txt"), "ok").unwrap();

        // Path traversal via ..
        let result = validate_source_in_context(context.path(), "../../../etc/passwd");
        assert!(result.is_err());
    }
}
