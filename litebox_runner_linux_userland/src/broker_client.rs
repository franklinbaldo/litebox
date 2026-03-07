// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! gRPC client that implements [`litebox::fs::broker::BrokerTransport`].
//!
//! This module provides [`GrpcBrokerTransport`], which wraps a Tonic gRPC
//! client and exposes it as a synchronous [`BrokerTransport`] suitable for use
//! inside the litebox `no_std` core.

use litebox::fs::broker::{BrokerTransport, RemoteDirEntry, RemoteError, RemoteFileStatus};
use litebox_broker::proto::file_broker_client::FileBrokerClient;
use litebox_broker::proto::{self};
use tokio::runtime::Runtime;
use tonic::transport::Channel;

/// A [`BrokerTransport`] backed by a Tonic gRPC client.
///
/// Internally holds a Tokio runtime so that the synchronous [`BrokerTransport`]
/// methods can block on async gRPC calls.
pub struct GrpcBrokerTransport {
    runtime: Runtime,
    client: std::sync::Mutex<FileBrokerClient<Channel>>,
}

impl GrpcBrokerTransport {
    /// Connect to a broker at the given `endpoint` (e.g., `http://127.0.0.1:50051`).
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established.
    pub fn connect(endpoint: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Runtime::new()?;
        let client =
            runtime.block_on(async { FileBrokerClient::connect(endpoint.to_string()).await })?;
        Ok(Self {
            runtime,
            client: std::sync::Mutex::new(client),
        })
    }
}

/// Map a gRPC `Status` to a [`RemoteError`].
///
/// Attempts to parse the errno from the status message; defaults to EIO (5).
fn status_to_remote_error(status: tonic::Status) -> RemoteError {
    // Try to extract an errno from the message (e.g., "errno:2").
    let errno = status
        .message()
        .strip_prefix("errno:")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(5); // EIO
    RemoteError { errno }
}

fn proto_file_type_to_u8(ft: i32) -> u8 {
    // proto::FileType enum values match our RemoteFileStatus encoding.
    u8::try_from(ft).unwrap_or(0)
}

impl BrokerTransport for GrpcBrokerTransport {
    fn open(&self, path: &str, flags: u32, mode: u32) -> Result<u64, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.open(proto::OpenRequest {
                path: path.into(),
                flags,
                mode,
            }))
            .map_err(status_to_remote_error)?;
        Ok(resp.into_inner().fd)
    }

    fn close(&self, fd: u64) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.close(proto::CloseRequest { fds: vec![fd] }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn read(&self, fd: u64, count: u32, offset: Option<u64>) -> Result<Vec<u8>, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.read(proto::ReadRequest { fd, count, offset }))
            .map_err(status_to_remote_error)?;
        Ok(resp.into_inner().data)
    }

    fn write(&self, fd: u64, data: &[u8], offset: Option<u64>) -> Result<usize, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.write(proto::WriteRequest {
                fd,
                data: data.to_vec(),
                offset,
            }))
            .map_err(status_to_remote_error)?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u64 file size fits in usize on 64-bit"
        )]
        Ok(resp.into_inner().count as usize)
    }

    fn seek(&self, fd: u64, offset: i64, whence: u32) -> Result<u64, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.seek(proto::SeekRequest { fd, offset, whence }))
            .map_err(status_to_remote_error)?;
        Ok(resp.into_inner().offset)
    }

    fn truncate(&self, fd: u64, length: u64) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.truncate(proto::TruncateRequest { fd, length }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn chmod(&self, path: &str, mode: u32) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.chmod(proto::ChmodRequest {
                path: path.into(),
                mode,
            }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn stat(&self, path: &str) -> Result<RemoteFileStatus, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.stat(proto::StatRequest { path: path.into() }))
            .map_err(status_to_remote_error)?;
        Ok(proto_stat_to_remote(resp.into_inner()))
    }

    fn fd_stat(&self, fd: u64) -> Result<RemoteFileStatus, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.fd_stat(proto::FdStatRequest { fd }))
            .map_err(status_to_remote_error)?;
        Ok(proto_stat_to_remote(resp.into_inner()))
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.mkdir(proto::MkdirRequest {
                path: path.into(),
                mode,
            }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn rmdir(&self, path: &str) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.rmdir(proto::RmdirRequest { path: path.into() }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), RemoteError> {
        let mut client = self.client.lock().unwrap();
        self.runtime
            .block_on(client.unlink(proto::UnlinkRequest { path: path.into() }))
            .map_err(status_to_remote_error)?;
        Ok(())
    }

    fn read_dir(&self, fd: u64) -> Result<Vec<RemoteDirEntry>, RemoteError> {
        let mut client = self.client.lock().unwrap();
        let resp = self
            .runtime
            .block_on(client.read_dir(proto::ReadDirRequest { fd }))
            .map_err(status_to_remote_error)?;
        Ok(resp
            .into_inner()
            .entries
            .into_iter()
            .map(|e| RemoteDirEntry {
                name: e.name,
                file_type: proto_file_type_to_u8(e.file_type),
            })
            .collect())
    }
}

fn proto_stat_to_remote(s: proto::StatResponse) -> RemoteFileStatus {
    RemoteFileStatus {
        file_type: proto_file_type_to_u8(s.file_type),
        mode: s.mode,
        size: s.size,
        uid: s.uid,
        gid: s.gid,
        dev: s.dev,
        ino: s.ino,
        rdev: s.rdev,
        blksize: s.blksize,
    }
}
