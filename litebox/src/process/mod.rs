// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process management abstractions for multi-process support.
//!
//! This module provides the core identity types ([`ProcessId`], [`ProcessGroupId`],
//! [`SessionId`]) and the [`ProcessRegistry`] for managing multiple guest processes
//! within LiteBox.
//!
//! See `docs/multi-process-single-address-space.md` for the full design.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::platform::RawMutex as RawMutexTrait;
use crate::sync::{RawSyncPrimitivesProvider, RwLock};

// ---------------------------------------------------------------------------
// Identity types
// ---------------------------------------------------------------------------

/// A process identifier, analogous to Linux's `tgid`.
///
/// Process IDs are monotonically allocated starting from 1 and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    /// The initial guest process.
    pub const INIT: Self = Self(1);

    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// A process group identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGroupId(u32);

impl ProcessGroupId {
    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<ProcessId> for ProcessGroupId {
    fn from(pid: ProcessId) -> Self {
        Self(pid.0)
    }
}

/// A session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u32);

impl SessionId {
    /// Returns the raw numeric value.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<ProcessId> for SessionId {
    fn from(pid: ProcessId) -> Self {
        Self(pid.0)
    }
}

// ---------------------------------------------------------------------------
// Process state & context
// ---------------------------------------------------------------------------

/// The lifecycle state of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is running (or runnable).
    Running,
    /// The process has exited with the given status but has not yet been reaped.
    Zombie(i32),
}

/// Pure identity and lifecycle data for a process (platform-agnostic).
#[derive(Debug)]
pub struct ProcessContext {
    /// This process's ID (tgid).
    pub id: ProcessId,
    /// Parent process ID. `None` only for the init process (PID 1).
    pub parent: Option<ProcessId>,
    /// Process group ID. Defaults to the parent's pgid, or `pid` for init.
    pub pgid: ProcessGroupId,
    /// Session ID. Defaults to the parent's sid, or `pid` for init.
    pub sid: SessionId,
    /// Signal sent to parent on exit (typically `SIGCHLD` for fork, 0 for threads).
    pub exit_signal: i32,
    /// Current lifecycle state.
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// Wait types
// ---------------------------------------------------------------------------

/// The target of a `waitpid`-style call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTarget {
    /// Wait for a specific child by PID.
    Pid(ProcessId),
    /// Wait for any child (`waitpid(-1, ...)`).
    AnyChild,
    /// Wait for any child in the given process group.
    ProcessGroup(ProcessGroupId),
}

/// Options for `waitpid`-style calls (matches Linux flag values).
bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct WaitOptions: u32 {
        /// Return immediately if no child has exited.
        const WNOHANG    = 1;
        /// Also report stopped children.
        const WUNTRACED  = 2;
        /// Also report continued children.
        const WCONTINUED = 8;
    }
}

/// Result of a successful reap via [`ProcessRegistry::wait_for_child`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitResult {
    /// PID of the reaped child.
    pub pid: ProcessId,
    /// Exit status of the child.
    pub status: i32,
}

/// Errors from [`ProcessRegistry::wait_for_child`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitError {
    /// No children (or no matching children) exist for this parent.
    NoChildren,
    /// `WNOHANG` was specified and no child has exited yet.
    WouldBlock,
    /// The specified process was not found in the registry.
    NoSuchProcess,
}

/// Errors from [`ProcessRegistry::create_process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateProcessError {
    /// The specified parent PID does not exist in the registry.
    NoSuchParent,
    /// A root (init) process already exists; only one is allowed.
    InitAlreadyExists,
}
// ---------------------------------------------------------------------------
// Wait notification channel (futex-based)
// ---------------------------------------------------------------------------

/// A per-process notification channel used by `waitpid`.
///
/// When a child exits, the parent's channel is signaled. Parents block on
/// their channel when no zombie child is available. Implemented using the
/// platform's [`RawMutex`](RawMutexTrait) (which has futex semantics).
struct WaitChannel<RawMutex: RawMutexTrait> {
    futex: RawMutex,
}

impl<RawMutex: RawMutexTrait> WaitChannel<RawMutex> {
    fn new() -> Self {
        Self {
            futex: RawMutex::INIT,
        }
    }

    /// Signal that a child has exited — wakes all waiters.
    fn notify(&self) {
        self.futex
            .underlying_atomic()
            .fetch_add(1, Ordering::Release);
        self.futex.wake_all();
    }

    /// Capture the current futex value. Must be called while the table lock
    /// is held so that any concurrent `notify()` will invalidate this snapshot.
    fn snapshot(&self) -> u32 {
        self.futex.underlying_atomic().load(Ordering::Acquire)
    }

    /// Block until the futex value differs from `snapshot`.
    /// Call this after releasing the table lock.
    fn block(&self, snapshot: u32) {
        let _ = self.futex.block(snapshot);
    }
}

// ---------------------------------------------------------------------------
// Internal per-process entry
// ---------------------------------------------------------------------------

/// Entry stored in the process table for each process.
struct ProcessEntry<Platform: RawSyncPrimitivesProvider> {
    context: ProcessContext,
    children: Vec<ProcessId>,
    /// Notification channel for this process's `waitpid` callers.
    /// Wrapped in [`Arc`] so it can be held outside the table lock.
    wait_channel: Arc<WaitChannel<Platform::RawMutex>>,
}

// ---------------------------------------------------------------------------
// ProcessRegistry
// ---------------------------------------------------------------------------

/// A registry of all processes in the system.
///
/// Manages process contexts, PID allocation, parent-child relationships,
/// and wait/notify for process exit. This is a concrete struct in core
/// (not a platform trait), parameterized only by the platform's sync primitives.
pub struct ProcessRegistry<Platform: RawSyncPrimitivesProvider> {
    table: RwLock<Platform, hashbrown::HashMap<ProcessId, ProcessEntry<Platform>>>,
    next_pid: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider> Default for ProcessRegistry<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Platform: RawSyncPrimitivesProvider> ProcessRegistry<Platform> {
    /// Create a new, empty process registry.
    pub fn new() -> Self {
        Self {
            table: RwLock::new(hashbrown::HashMap::new()),
            next_pid: AtomicU32::new(1),
        }
    }

    /// Create a new process and return its [`ProcessId`].
    ///
    /// If `parent` is `None`, this creates the init process (PID 1) with no
    /// parent and `exit_signal = 0`. Otherwise, the new process inherits
    /// `pgid` and `sid` from the parent and is registered as the parent's
    /// child. The caller supplies `exit_signal` — the signal (in the platform's
    /// numbering) delivered to the parent when this process exits; typically
    /// `SIGCHLD` for fork-style children, 0 for threads.
    ///
    /// # Errors
    ///
    /// Returns [`CreateProcessError::NoSuchParent`] if `parent` is `Some` but
    /// the parent PID is not in the registry, or
    /// [`CreateProcessError::InitAlreadyExists`] if `parent` is `None` and a
    /// root process already exists.
    pub fn create_process(
        &self,
        parent: Option<ProcessId>,
        exit_signal: i32,
    ) -> Result<ProcessId, CreateProcessError> {
        let raw = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let new_pid = ProcessId(raw);

        let mut table = self.table.write();

        let (pgid, sid) = if let Some(parent_pid) = parent {
            let parent_entry = table
                .get_mut(&parent_pid)
                .ok_or(CreateProcessError::NoSuchParent)?;
            parent_entry.children.push(new_pid);
            (parent_entry.context.pgid, parent_entry.context.sid)
        } else {
            if table.values().any(|e| e.context.parent.is_none()) {
                return Err(CreateProcessError::InitAlreadyExists);
            }
            (ProcessGroupId::from(new_pid), SessionId::from(new_pid))
        };

        let entry = ProcessEntry {
            context: ProcessContext {
                id: new_pid,
                parent,
                pgid,
                sid,
                exit_signal,
                state: ProcessState::Running,
            },
            children: Vec::new(),
            wait_channel: Arc::new(WaitChannel::new()),
        };

        let prev = table.insert(new_pid, entry);
        debug_assert!(prev.is_none(), "PID collision: {}", new_pid.0);

        Ok(new_pid)
    }

    /// Mark a process as exited with the given status.
    ///
    /// The process transitions to [`ProcessState::Zombie`]. Its children are
    /// reparented to PID 1 (the init process), and any zombie orphans are
    /// automatically reaped. The parent's wait channel is notified.
    ///
    /// # Panics
    ///
    /// Panics if `id` is not in the registry or the process has already exited.
    pub fn exit_process(&self, id: ProcessId, status: i32) {
        let parent_wait_channel;

        {
            let mut table = self.table.write();

            let entry = table.get_mut(&id).expect("process must exist");

            // Guard against double-exit. In release builds the debug_assert
            // would be stripped, so we check unconditionally.
            if matches!(entry.context.state, ProcessState::Zombie(_)) {
                return;
            }
            entry.context.state = ProcessState::Zombie(status);

            let parent = entry.context.parent;

            // In Linux, init (PID 1) exiting is a kernel panic. In LiteBox,
            // we allow it (sandbox teardown) but skip reparenting since there
            // is no ancestor to reparent to.
            if id != ProcessId::INIT {
                let orphaned_children: Vec<ProcessId> = entry.children.drain(..).collect();
                if !orphaned_children.is_empty() {
                    // Separate zombie orphans (auto-reap) from running orphans (reparent).
                    let mut zombies_to_reap = Vec::new();
                    let mut to_reparent = Vec::new();
                    for &child_pid in &orphaned_children {
                        let is_zombie = table
                            .get(&child_pid)
                            .is_some_and(|e| matches!(e.context.state, ProcessState::Zombie(_)));
                        if is_zombie {
                            zombies_to_reap.push(child_pid);
                        } else {
                            to_reparent.push(child_pid);
                        }
                    }

                    // Reparent running children to PID 1.
                    for &child_pid in &to_reparent {
                        if let Some(child_entry) = table.get_mut(&child_pid) {
                            child_entry.context.parent = Some(ProcessId::INIT);
                        }
                    }
                    if let Some(init_entry) = table.get_mut(&ProcessId::INIT) {
                        init_entry.children.extend(to_reparent);
                    }

                    // Auto-reap zombie orphans.
                    for pid in zombies_to_reap {
                        table.remove(&pid);
                    }
                }
            }

            // Clone the parent's wait channel (if parent exists and is
            // running) before dropping the lock. If the parent is already a
            // zombie (or gone), nobody will ever reap us, so auto-reap now.
            parent_wait_channel = match parent {
                Some(parent_pid) => match table.get(&parent_pid) {
                    Some(pe) if matches!(pe.context.state, ProcessState::Running) => {
                        Some(Arc::clone(&pe.wait_channel))
                    }
                    _ => {
                        // Parent is zombie or missing — auto-reap ourselves
                        // and remove from parent's children list.
                        table.remove(&id);
                        if let Some(pe) = table.get_mut(&parent_pid) {
                            pe.children.retain(|&c| c != id);
                        }
                        None
                    }
                },
                None => None,
            };
        }

        // Notify the parent outside the table lock.
        if let Some(wc) = parent_wait_channel {
            wc.notify();
        }
    }

    /// Wait for a child process to exit (`waitpid` semantics).
    ///
    /// Blocks unless `WNOHANG` is set in `options`. On success, the zombie
    /// child is reaped (removed from the registry) and its status returned.
    ///
    /// # Panics
    ///
    /// Panics if the parent disappears from the registry during a blocking wait.
    pub fn wait_for_child(
        &self,
        parent: ProcessId,
        target: WaitTarget,
        options: WaitOptions,
    ) -> Result<WaitResult, WaitError> {
        loop {
            let wait_channel;
            let wait_snapshot;

            {
                let mut table = self.table.write();

                let parent_entry = table.get(&parent).ok_or(WaitError::NoSuchProcess)?;

                // Check that the parent has at least one child matching the target.
                let has_matching_child = parent_entry
                    .children
                    .iter()
                    .any(|&child_pid| Self::matches_target(&table, child_pid, target));

                if !has_matching_child {
                    return Err(WaitError::NoChildren);
                }

                // Look for a zombie child matching the target.
                let zombie = parent_entry
                    .children
                    .iter()
                    .filter(|&&child_pid| Self::matches_target(&table, child_pid, target))
                    .find_map(|&child_pid| {
                        let child = table.get(&child_pid)?;
                        if let ProcessState::Zombie(status) = child.context.state {
                            Some((child_pid, status))
                        } else {
                            None
                        }
                    });

                if let Some((zombie_pid, status)) = zombie {
                    // Reap: remove from table and from parent's children list.
                    table.remove(&zombie_pid);
                    if let Some(parent_entry) = table.get_mut(&parent) {
                        parent_entry.children.retain(|&pid| pid != zombie_pid);
                    }
                    return Ok(WaitResult {
                        pid: zombie_pid,
                        status,
                    });
                }

                if options.contains(WaitOptions::WNOHANG) {
                    return Err(WaitError::WouldBlock);
                }

                // Clone the parent's wait channel and snapshot the futex
                // while the lock is held, so any concurrent notify() will
                // invalidate the snapshot.
                let (wc, snapshot) = {
                    let entry = table.get(&parent).expect("parent still exists");
                    (
                        Arc::clone(&entry.wait_channel),
                        entry.wait_channel.snapshot(),
                    )
                };
                wait_channel = wc;
                wait_snapshot = snapshot;
            }

            // Block outside the table lock until a child exits.
            wait_channel.block(wait_snapshot);
            // Re-acquire the lock and re-check (loop).
        }
    }

    /// Read a process's context through a closure (avoids exposing the lock).
    pub fn with_context<R>(
        &self,
        id: ProcessId,
        f: impl FnOnce(&ProcessContext) -> R,
    ) -> Option<R> {
        let table = self.table.read();
        table.get(&id).map(|entry| f(&entry.context))
    }

    /// Returns the parent PID of the given process, or `None` if it has no parent.
    pub fn get_parent(&self, id: ProcessId) -> Option<ProcessId> {
        self.with_context(id, |ctx| ctx.parent)?
    }

    /// Returns the list of child PIDs for the given process.
    pub fn get_children(&self, id: ProcessId) -> Option<Vec<ProcessId>> {
        let table = self.table.read();
        table.get(&id).map(|entry| entry.children.clone())
    }

    /// Returns the number of processes currently tracked (including zombies).
    pub fn process_count(&self) -> usize {
        self.table.read().len()
    }

    /// Check if a child PID matches the given wait target.
    fn matches_target(
        table: &hashbrown::HashMap<ProcessId, ProcessEntry<Platform>>,
        child_pid: ProcessId,
        target: WaitTarget,
    ) -> bool {
        debug_assert!(
            table.contains_key(&child_pid),
            "child PID {} in parent's children list but missing from table",
            child_pid.as_u32()
        );
        match target {
            WaitTarget::Pid(target_pid) => child_pid == target_pid,
            WaitTarget::AnyChild => true,
            WaitTarget::ProcessGroup(pgid) => table
                .get(&child_pid)
                .is_some_and(|e| e.context.pgid == pgid),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::LiteBox;
    use crate::platform::mock::MockPlatform;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    fn setup() -> (
        &'static MockPlatform,
        alloc::sync::Arc<ProcessRegistry<MockPlatform>>,
    ) {
        let platform = MockPlatform::new();
        let _litebox = LiteBox::new(platform);
        let registry = alloc::sync::Arc::new(ProcessRegistry::new());
        (platform, registry)
    }

    #[test]
    fn test_create_init_process() {
        let (_platform, registry) = setup();
        let pid = registry.create_process(None, 0).unwrap();
        assert_eq!(pid, ProcessId::INIT);

        registry
            .with_context(pid, |ctx| {
                assert_eq!(ctx.id, ProcessId::INIT);
                assert_eq!(ctx.parent, None);
                assert_eq!(ctx.pgid, ProcessGroupId::from(pid));
                assert_eq!(ctx.sid, SessionId::from(pid));
                assert_eq!(ctx.exit_signal, 0);
                assert_eq!(ctx.state, ProcessState::Running);
            })
            .expect("init process should exist");
    }

    #[test]
    fn test_create_child_process() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        assert_ne!(parent, child);
        assert!(child.as_u32() > parent.as_u32());

        registry
            .with_context(child, |ctx| {
                assert_eq!(ctx.parent, Some(parent));
                // Inherits parent's pgid/sid
                assert_eq!(ctx.pgid, ProcessGroupId::from(parent));
                assert_eq!(ctx.sid, SessionId::from(parent));
                assert_eq!(ctx.exit_signal, 17);
                assert_eq!(ctx.state, ProcessState::Running);
            })
            .expect("child process should exist");

        // Parent should list child
        let children = registry.get_children(parent).unwrap();
        assert_eq!(children, alloc::vec![child]);
    }

    #[test]
    fn test_pid_allocation_monotonic() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let p2 = registry.create_process(Some(init), 17).unwrap();
        let p3 = registry.create_process(Some(init), 17).unwrap();
        let p4 = registry.create_process(Some(init), 17).unwrap();

        assert!(p2.as_u32() > init.as_u32());
        assert!(p3.as_u32() > p2.as_u32());
        assert!(p4.as_u32() > p3.as_u32());
    }

    #[test]
    fn test_exit_process_becomes_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 42);

        registry
            .with_context(child, |ctx| {
                assert_eq!(ctx.state, ProcessState::Zombie(42));
            })
            .expect("zombie should still be in table");
    }

    #[test]
    fn test_wait_for_child_nohang_reaps_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 7);

        let result = registry
            .wait_for_child(parent, WaitTarget::AnyChild, WaitOptions::WNOHANG)
            .expect("should reap zombie");
        assert_eq!(result.pid, child);
        assert_eq!(result.status, 7);

        // Zombie should be removed from the table
        assert!(registry.with_context(child, |_| ()).is_none());
        // Parent should have no children left
        assert!(registry.get_children(parent).unwrap().is_empty());
    }

    #[test]
    fn test_wait_for_child_nohang_no_zombie() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let _child = registry.create_process(Some(parent), 17).unwrap();

        let result = registry.wait_for_child(parent, WaitTarget::AnyChild, WaitOptions::WNOHANG);
        assert_eq!(result, Err(WaitError::WouldBlock));
    }

    #[test]
    fn test_wait_no_children() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();

        let result = registry.wait_for_child(parent, WaitTarget::AnyChild, WaitOptions::WNOHANG);
        assert_eq!(result, Err(WaitError::NoChildren));
    }

    #[test]
    fn test_wait_for_specific_child() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(parent), 17).unwrap();
        let child2 = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child1, 10);
        registry.exit_process(child2, 20);

        // Wait for child2 specifically
        let result = registry
            .wait_for_child(parent, WaitTarget::Pid(child2), WaitOptions::WNOHANG)
            .expect("should reap child2");
        assert_eq!(result.pid, child2);
        assert_eq!(result.status, 20);

        // child1 should still be a zombie
        registry
            .with_context(child1, |ctx| {
                assert_eq!(ctx.state, ProcessState::Zombie(10));
            })
            .expect("child1 should still exist");
    }

    #[test]
    fn test_wait_for_child_blocks_until_exit() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        let registry_clone = alloc::sync::Arc::clone(&registry);
        let barrier = alloc::sync::Arc::new(Barrier::new(2));
        let barrier_clone = alloc::sync::Arc::clone(&barrier);

        // Spawn a thread that will exit the child after a delay.
        let exit_thread = thread::spawn(move || {
            barrier_clone.wait();
            thread::sleep(Duration::from_millis(20));
            registry_clone.exit_process(child, 99);
        });

        barrier.wait();

        // This should block until the child exits.
        let result = registry
            .wait_for_child(parent, WaitTarget::AnyChild, WaitOptions::empty())
            .expect("should reap child");
        assert_eq!(result.pid, child);
        assert_eq!(result.status, 99);

        exit_thread.join().unwrap();
    }

    #[test]
    fn test_reparent_children_on_exit() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let mid = registry.create_process(Some(init), 17).unwrap();
        let grandchild = registry.create_process(Some(mid), 17).unwrap();

        // Mid exits — grandchild should be reparented to init.
        registry.exit_process(mid, 0);

        registry
            .with_context(grandchild, |ctx| {
                assert_eq!(ctx.parent, Some(ProcessId::INIT));
            })
            .expect("grandchild should exist");

        // Init should now list grandchild as a child.
        let init_children = registry.get_children(init).unwrap();
        assert!(init_children.contains(&grandchild));
    }

    #[test]
    fn test_auto_reap_zombie_orphans() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let mid = registry.create_process(Some(init), 17).unwrap();
        let grandchild = registry.create_process(Some(mid), 17).unwrap();

        // Grandchild exits first (becomes zombie under mid).
        registry.exit_process(grandchild, 5);
        assert!(registry.with_context(grandchild, |_| ()).is_some());

        // Mid exits — zombie grandchild should be auto-reaped.
        registry.exit_process(mid, 0);
        assert!(
            registry.with_context(grandchild, |_| ()).is_none(),
            "zombie orphan should have been auto-reaped"
        );
    }

    #[test]
    fn test_process_count() {
        let (_platform, registry) = setup();
        assert_eq!(registry.process_count(), 0);

        let init = registry.create_process(None, 0).unwrap();
        assert_eq!(registry.process_count(), 1);

        let child = registry.create_process(Some(init), 17).unwrap();
        assert_eq!(registry.process_count(), 2);

        registry.exit_process(child, 0);
        // Zombie still counted
        assert_eq!(registry.process_count(), 2);

        // Reap
        registry
            .wait_for_child(init, WaitTarget::AnyChild, WaitOptions::WNOHANG)
            .unwrap();
        assert_eq!(registry.process_count(), 1);
    }

    #[test]
    fn test_wait_for_process_group() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child1 = registry.create_process(Some(init), 17).unwrap();
        let child2 = registry.create_process(Some(init), 17).unwrap();

        // Both children inherit init's pgid (which is ProcessGroupId(1))
        let init_pgid = ProcessGroupId::from(init);

        registry.exit_process(child1, 11);

        let result = registry
            .wait_for_child(
                init,
                WaitTarget::ProcessGroup(init_pgid),
                WaitOptions::WNOHANG,
            )
            .expect("should reap child in same process group");
        assert_eq!(result.pid, child1);
        assert_eq!(result.status, 11);

        // child2 still running, so WouldBlock
        let result = registry.wait_for_child(
            init,
            WaitTarget::ProcessGroup(init_pgid),
            WaitOptions::WNOHANG,
        );
        assert_eq!(result, Err(WaitError::WouldBlock));
    }

    #[test]
    fn test_no_such_process() {
        let (_platform, registry) = setup();
        let bogus = ProcessId(999);
        let result = registry.wait_for_child(bogus, WaitTarget::AnyChild, WaitOptions::WNOHANG);
        assert_eq!(result, Err(WaitError::NoSuchProcess));
    }

    #[test]
    fn test_create_with_missing_parent_returns_error() {
        let (_platform, registry) = setup();
        let _init = registry.create_process(None, 0).unwrap();
        let bogus_parent = ProcessId(999);
        let result = registry.create_process(Some(bogus_parent), 17);
        assert_eq!(result, Err(CreateProcessError::NoSuchParent));
    }

    #[test]
    fn test_double_exit_is_idempotent() {
        let (_platform, registry) = setup();
        let parent = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(parent), 17).unwrap();

        registry.exit_process(child, 42);
        // Second exit must not panic or overwrite the status.
        registry.exit_process(child, 99);

        let result = registry
            .wait_for_child(parent, WaitTarget::AnyChild, WaitOptions::WNOHANG)
            .expect("should reap zombie");
        assert_eq!(result.status, 42, "first exit status must be preserved");
    }

    #[test]
    fn test_duplicate_root_returns_error() {
        let (_platform, registry) = setup();
        let _init = registry.create_process(None, 0).unwrap();
        // Second root should return an error.
        let result = registry.create_process(None, 0);
        assert_eq!(result, Err(CreateProcessError::InitAlreadyExists));
    }

    #[test]
    fn test_child_auto_reaped_when_parent_is_zombie() {
        let (_platform, registry) = setup();
        let init = registry.create_process(None, 0).unwrap();
        let child = registry.create_process(Some(init), 17).unwrap();

        // Init exits first (sandbox teardown scenario).
        registry.exit_process(init, 0);

        // Child exits — should be auto-reaped since parent is zombie.
        registry.exit_process(child, 1);

        // Child should no longer be in the table.
        assert!(
            registry.with_context(child, |_| ()).is_none(),
            "child should have been auto-reaped"
        );
    }
}
