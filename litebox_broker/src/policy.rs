// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Policy engine abstraction for the file broker.
//!
//! Provides a [`Policy`] trait that the broker consults on every file system
//! operation.  The default [`AllowAllPolicy`] permits everything — swap it out
//! for an Oso-backed implementation when the policy engine is integrated.

use std::path::Path;

/// The kind of file system operation being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Open,
    Read,
    Write,
    Stat,
    Chmod,
    Mkdir,
    Rmdir,
    Unlink,
    ReadDir,
    Truncate,
    Seek,
    Close,
}

/// Outcome of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Policy engine consulted by the broker before performing host FS operations.
pub trait Policy: Send + Sync {
    /// Decide whether `action` is permitted on `path`.
    ///
    /// `path` is always relative to the broker's root directory.  An `None`
    /// path indicates an FD-only operation where no path context is available.
    fn check(&self, action: Action, path: Option<&Path>) -> Decision;

    /// Load or replace the policy rules from `text`.
    ///
    /// Returns an error message on failure.
    fn load_rules(&self, text: &str) -> Result<(), String>;
}

/// A policy that allows only read-only operations.
///
/// Write, Chmod, Mkdir, Rmdir, Unlink, and Truncate are denied.
/// Open, Read, Stat, ReadDir, Seek, and Close are permitted.
#[derive(Debug, Default)]
pub struct ReadOnlyPolicy;

impl Policy for ReadOnlyPolicy {
    fn check(&self, action: Action, _path: Option<&Path>) -> Decision {
        match action {
            Action::Open
            | Action::Read
            | Action::Stat
            | Action::ReadDir
            | Action::Seek
            | Action::Close => Decision::Allow,
            Action::Write
            | Action::Chmod
            | Action::Mkdir
            | Action::Rmdir
            | Action::Unlink
            | Action::Truncate => Decision::Deny,
        }
    }

    fn load_rules(&self, _text: &str) -> Result<(), String> {
        Err("ReadOnlyPolicy does not support dynamic rules".into())
    }
}

/// A policy that allows every operation unconditionally.
///
/// This is a development-time stub.  Replace with an Oso-backed policy for
/// production use.
#[derive(Debug, Default)]
pub struct AllowAllPolicy;

impl Policy for AllowAllPolicy {
    fn check(&self, _action: Action, _path: Option<&Path>) -> Decision {
        Decision::Allow
    }

    fn load_rules(&self, _text: &str) -> Result<(), String> {
        Ok(())
    }
}
