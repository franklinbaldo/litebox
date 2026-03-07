// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! gRPC service implementation for the `FileBroker` service.
//!
//! The server translates each RPC into a host filesystem operation, after
//! consulting the [`Policy`](crate::policy::Policy) engine.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tonic::{Request, Response, Status};

use crate::policy::{Action, Decision, Policy};
use crate::proto::file_broker_server::FileBroker;
use crate::proto::{self};

/// State for a single open file descriptor on the broker side.
struct OpenFile {
    file: fs::File,
    path: PathBuf,
}

/// Implementation of the `FileBroker` gRPC service.
pub struct FileBrokerService {
    /// Root directory that the broker exposes.
    root: PathBuf,
    /// Policy engine.
    policy: Arc<dyn Policy>,
    /// Open file descriptors, keyed by broker-assigned FDID.
    open_files: Mutex<HashMap<u64, OpenFile>>,
    /// Monotonically increasing FDID counter.
    next_fd: AtomicU64,
}

impl FileBrokerService {
    /// Create a new service rooted at `root` with the given `policy`.
    pub fn new(root: PathBuf, policy: Arc<dyn Policy>) -> Self {
        Self {
            root,
            policy,
            open_files: Mutex::new(HashMap::new()),
            // Reserve FD 0 for the root (assigned in Mount).
            next_fd: AtomicU64::new(1),
        }
    }

    /// Allocate a new FDID.
    fn alloc_fd(&self) -> u64 {
        self.next_fd.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolve a relative path against the root, ensuring containment.
    fn resolve_path(&self, relative: &str) -> Result<PathBuf, Status> {
        let relative = relative.trim_start_matches('/');
        let candidate = self.root.join(relative);
        let canonical = candidate
            .canonicalize()
            .map_err(|e| Status::not_found(format!("path resolution failed: {e}")))?;
        if !canonical.starts_with(&self.root) {
            return Err(Status::permission_denied("path escapes root"));
        }
        Ok(canonical)
    }

    /// Check policy and return `Err(Status)` on denial.
    fn check_policy(&self, action: Action, path: Option<&Path>) -> Result<(), Status> {
        if self.policy.check(action, path) == Decision::Deny {
            return Err(Status::permission_denied(format!(
                "{action:?} denied by policy"
            )));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl FileBroker for FileBrokerService {
    async fn mount(
        &self,
        _request: Request<proto::MountRequest>,
    ) -> Result<Response<proto::MountResponse>, Status> {
        Ok(Response::new(proto::MountResponse {
            root_fd: 0,
            max_message_size: 4 * 1024 * 1024,
        }))
    }

    async fn open(
        &self,
        request: Request<proto::OpenRequest>,
    ) -> Result<Response<proto::OpenResponse>, Status> {
        let req = request.into_inner();
        let resolved = self.resolve_path(&req.path)?;
        self.check_policy(Action::Open, Some(&resolved))?;

        let mut opts = fs::OpenOptions::new();
        let flags = req.flags;

        // Map Linux O_* flags to Rust OpenOptions.
        let access_mode = flags & 0x3;
        match access_mode {
            0 => {
                opts.read(true);
            }
            1 => {
                opts.write(true);
            }
            2 => {
                opts.read(true).write(true);
            }
            _ => {
                opts.read(true);
            }
        }
        if flags & 0x40 != 0 {
            // O_CREAT
            opts.create(true);
        }
        if flags & 0x80 != 0 {
            // O_EXCL
            opts.create_new(true);
        }
        if flags & 0x200 != 0 {
            // O_TRUNC
            opts.truncate(true);
        }
        if flags & 0x400 != 0 {
            // O_APPEND
            opts.append(true);
        }

        let file = opts
            .open(&resolved)
            .map_err(|e| Status::internal(format!("open failed: {e}")))?;

        let fd = self.alloc_fd();
        self.open_files.lock().unwrap().insert(
            fd,
            OpenFile {
                file,
                path: resolved,
            },
        );

        Ok(Response::new(proto::OpenResponse { fd }))
    }

    async fn close(
        &self,
        request: Request<proto::CloseRequest>,
    ) -> Result<Response<proto::CloseResponse>, Status> {
        let req = request.into_inner();
        let mut files = self.open_files.lock().unwrap();
        for fd in req.fds {
            files.remove(&fd);
        }
        Ok(Response::new(proto::CloseResponse {}))
    }

    async fn read(
        &self,
        request: Request<proto::ReadRequest>,
    ) -> Result<Response<proto::ReadResponse>, Status> {
        let req = request.into_inner();
        let mut files = self.open_files.lock().unwrap();
        let entry = files
            .get_mut(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::Read, Some(&entry.path))?;

        if let Some(offset) = req.offset {
            entry
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| Status::internal(format!("seek failed: {e}")))?;
        }
        let mut buf = vec![0u8; req.count as usize];
        let n = entry
            .file
            .read(&mut buf)
            .map_err(|e| Status::internal(format!("read failed: {e}")))?;
        buf.truncate(n);

        Ok(Response::new(proto::ReadResponse { data: buf }))
    }

    async fn write(
        &self,
        request: Request<proto::WriteRequest>,
    ) -> Result<Response<proto::WriteResponse>, Status> {
        let req = request.into_inner();
        let mut files = self.open_files.lock().unwrap();
        let entry = files
            .get_mut(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::Write, Some(&entry.path))?;

        if let Some(offset) = req.offset {
            entry
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| Status::internal(format!("seek failed: {e}")))?;
        }
        let n = entry
            .file
            .write(&req.data)
            .map_err(|e| Status::internal(format!("write failed: {e}")))?;

        Ok(Response::new(proto::WriteResponse { count: n as u64 }))
    }

    async fn seek(
        &self,
        request: Request<proto::SeekRequest>,
    ) -> Result<Response<proto::SeekResponse>, Status> {
        let req = request.into_inner();
        let mut files = self.open_files.lock().unwrap();
        let entry = files
            .get_mut(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::Seek, Some(&entry.path))?;

        let whence = match req.whence {
            0 => SeekFrom::Start(req.offset as u64),
            1 => SeekFrom::Current(req.offset),
            2 => SeekFrom::End(req.offset),
            _ => return Err(Status::invalid_argument("invalid whence")),
        };
        let pos = entry
            .file
            .seek(whence)
            .map_err(|e| Status::internal(format!("seek failed: {e}")))?;

        Ok(Response::new(proto::SeekResponse { offset: pos }))
    }

    async fn truncate(
        &self,
        request: Request<proto::TruncateRequest>,
    ) -> Result<Response<proto::TruncateResponse>, Status> {
        let req = request.into_inner();
        let mut files = self.open_files.lock().unwrap();
        let entry = files
            .get_mut(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::Truncate, Some(&entry.path))?;

        entry
            .file
            .set_len(req.length)
            .map_err(|e| Status::internal(format!("truncate failed: {e}")))?;

        Ok(Response::new(proto::TruncateResponse {}))
    }

    async fn chmod(
        &self,
        request: Request<proto::ChmodRequest>,
    ) -> Result<Response<proto::ChmodResponse>, Status> {
        let req = request.into_inner();
        let resolved = self.resolve_path(&req.path)?;
        self.check_policy(Action::Chmod, Some(&resolved))?;

        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(req.mode);
        fs::set_permissions(&resolved, perms)
            .map_err(|e| Status::internal(format!("chmod failed: {e}")))?;

        Ok(Response::new(proto::ChmodResponse {}))
    }

    async fn stat(
        &self,
        request: Request<proto::StatRequest>,
    ) -> Result<Response<proto::StatResponse>, Status> {
        let req = request.into_inner();
        let resolved = self.resolve_path(&req.path)?;
        self.check_policy(Action::Stat, Some(&resolved))?;

        let meta =
            fs::metadata(&resolved).map_err(|e| Status::not_found(format!("stat failed: {e}")))?;

        Ok(Response::new(metadata_to_stat(&meta)))
    }

    async fn fd_stat(
        &self,
        request: Request<proto::FdStatRequest>,
    ) -> Result<Response<proto::StatResponse>, Status> {
        let req = request.into_inner();
        let files = self.open_files.lock().unwrap();
        let entry = files
            .get(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::Stat, Some(&entry.path))?;

        let meta = entry
            .file
            .metadata()
            .map_err(|e| Status::internal(format!("fstat failed: {e}")))?;

        Ok(Response::new(metadata_to_stat(&meta)))
    }

    async fn mkdir(
        &self,
        request: Request<proto::MkdirRequest>,
    ) -> Result<Response<proto::MkdirResponse>, Status> {
        let req = request.into_inner();
        // For mkdir the target doesn't exist yet, so resolve the parent.
        let relative = req.path.trim_start_matches('/');
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            let canonical_parent = parent
                .canonicalize()
                .map_err(|e| Status::not_found(format!("parent resolution failed: {e}")))?;
            if !canonical_parent.starts_with(&self.root) {
                return Err(Status::permission_denied("path escapes root"));
            }
        }
        self.check_policy(Action::Mkdir, Some(&target))?;

        fs::create_dir(&target).map_err(|e| Status::internal(format!("mkdir failed: {e}")))?;

        // Apply the requested permissions.
        use std::os::unix::fs::PermissionsExt;
        if req.mode != 0 {
            let perms = fs::Permissions::from_mode(req.mode);
            fs::set_permissions(&target, perms).ok();
        }

        Ok(Response::new(proto::MkdirResponse {}))
    }

    async fn rmdir(
        &self,
        request: Request<proto::RmdirRequest>,
    ) -> Result<Response<proto::RmdirResponse>, Status> {
        let req = request.into_inner();
        let resolved = self.resolve_path(&req.path)?;
        self.check_policy(Action::Rmdir, Some(&resolved))?;

        fs::remove_dir(&resolved).map_err(|e| Status::internal(format!("rmdir failed: {e}")))?;

        Ok(Response::new(proto::RmdirResponse {}))
    }

    async fn unlink(
        &self,
        request: Request<proto::UnlinkRequest>,
    ) -> Result<Response<proto::UnlinkResponse>, Status> {
        let req = request.into_inner();
        let resolved = self.resolve_path(&req.path)?;
        self.check_policy(Action::Unlink, Some(&resolved))?;

        fs::remove_file(&resolved).map_err(|e| Status::internal(format!("unlink failed: {e}")))?;

        Ok(Response::new(proto::UnlinkResponse {}))
    }

    async fn read_dir(
        &self,
        request: Request<proto::ReadDirRequest>,
    ) -> Result<Response<proto::ReadDirResponse>, Status> {
        let req = request.into_inner();
        let files = self.open_files.lock().unwrap();
        let entry = files
            .get(&req.fd)
            .ok_or_else(|| Status::not_found("bad fd"))?;

        self.check_policy(Action::ReadDir, Some(&entry.path))?;

        let dir_path = entry.path.clone();
        drop(files);

        let mut entries = Vec::new();
        let read_dir = fs::read_dir(&dir_path)
            .map_err(|e| Status::internal(format!("readdir failed: {e}")))?;
        for dir_entry in read_dir {
            let dir_entry =
                dir_entry.map_err(|e| Status::internal(format!("readdir entry: {e}")))?;
            let ft = dir_entry.file_type().ok();
            let file_type = match ft {
                Some(t) if t.is_dir() => proto::FileType::Directory,
                Some(t) if t.is_symlink() => proto::FileType::Symlink,
                Some(t) if t.is_file() => proto::FileType::Regular,
                _ => proto::FileType::Unknown,
            };
            entries.push(proto::DirEntry {
                name: dir_entry.file_name().to_string_lossy().into_owned(),
                file_type: file_type.into(),
            });
        }

        Ok(Response::new(proto::ReadDirResponse { entries }))
    }

    async fn load_policy(
        &self,
        request: Request<proto::LoadPolicyRequest>,
    ) -> Result<Response<proto::LoadPolicyResponse>, Status> {
        let req = request.into_inner();
        match self.policy.load_rules(&req.policy_text) {
            Ok(()) => Ok(Response::new(proto::LoadPolicyResponse {
                success: true,
                error_message: String::new(),
            })),
            Err(e) => Ok(Response::new(proto::LoadPolicyResponse {
                success: false,
                error_message: e,
            })),
        }
    }
}

/// Convert `std::fs::Metadata` into a `StatResponse`.
fn metadata_to_stat(meta: &fs::Metadata) -> proto::StatResponse {
    let file_type = if meta.is_dir() {
        proto::FileType::Directory
    } else if meta.is_symlink() {
        proto::FileType::Symlink
    } else if meta.is_file() {
        proto::FileType::Regular
    } else {
        proto::FileType::Unknown
    };

    proto::StatResponse {
        file_type: file_type.into(),
        mode: meta.mode(),
        size: meta.len(),
        uid: meta.uid(),
        gid: meta.gid(),
        dev: meta.dev(),
        ino: meta.ino(),
        rdev: meta.rdev(),
        blksize: meta.blksize(),
    }
}
