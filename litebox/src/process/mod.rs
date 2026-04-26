// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process identity and lifecycle management.
//!
//! This module provides a platform-agnostic process registry for tracking
//! parent-child relationships, exit status, and process lifecycle. OS-specific
//! semantics (POSIX process groups/sessions, NT job objects, etc.) belong in
//! the shim layer, not here.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use hashbrown::HashMap;
use thiserror::Error;

use crate::event::{Events, observer::Observer};
use crate::platform::RawMutex as RawMutexTrait;
use crate::sync::{Mutex, RawSyncPrimitivesProvider};

/// Process identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    /// The first process created in every LiteBox instance.
    pub const INIT: Self = Self(1);

    /// Create a new `ProcessId` from a raw value.
    /// Returns `None` if `raw` is 0 (invalid).
    pub fn new(raw: u32) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Get the raw `u32` value of this process ID.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Per-process state tracked by the core.
pub struct ProcessContext {
    pub id: ProcessId,
    /// Parent process. `None` only for the init process.
    pub parent: Option<ProcessId>,
    pub state: ProcessState,
    /// Process group ID. Defaults to the process's own PID.
    pub pgid: ProcessId,
    /// Session ID. Defaults to the process's own PID for the init process.
    pub sid: ProcessId,
    /// Child processes.
    children: Vec<ProcessId>,
}

impl ProcessContext {
    /// Get the list of child processes.
    pub fn children(&self) -> &[ProcessId] {
        &self.children
    }
}

/// Whether a process is running or has exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    /// The process has exited. The `u32` is opaque to the core;
    /// shims assign platform-specific meaning (POSIX: wait status encoding;
    /// NT: NTSTATUS / DWORD exit code, etc.).
    Exited(u32),
}

/// Returned by [`ProcessRegistry::exit_process`] so the shim can notify the
/// parent through whatever mechanism is appropriate (SIGCHLD, handle
/// signaling, etc.).
pub struct ExitNotification {
    pub parent_pid: ProcessId,
    pub child_pid: ProcessId,
    pub exit_status: u32,
}

/// Errors from [`ProcessRegistry::create_process`].
#[derive(Error, Debug)]
pub enum CreateProcessError {
    #[error("the specified parent PID does not exist in the registry")]
    NoSuchParent,
    #[error("a root (init) process already exists")]
    InitAlreadyExists,
    #[error("too many processes (limit: {0})")]
    TooManyProcesses(usize),
    #[error("PID space exhausted")]
    PidSpaceExhausted,
}

/// Shared handle for observing a process's exit.
///
/// `exited` becomes `true` when the process exits. `observer` is notified
/// with readiness events so shims can integrate with their event loop.
pub struct ProcessExitObserver<Platform: RawSyncPrimitivesProvider> {
    /// Whether the process has exited.
    pub exited: Arc<AtomicBool>,
    /// Observer that receives [`Events::IN`] when the process exits.
    pub observer: Arc<ExitSubject<Platform>>,
}

/// An exit notification subject that observers can register on.
pub struct ExitSubject<Platform: RawSyncPrimitivesProvider> {
    observers: Mutex<Platform, Vec<alloc::sync::Weak<dyn Observer<Events>>>>,
    notified: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider> ExitSubject<Platform> {
    fn new() -> Self {
        Self {
            observers: Mutex::new(Vec::new()),
            notified: AtomicBool::new(false),
        }
    }

    /// Register an observer to be notified when the process exits.
    pub fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>) {
        let fire_immediately;
        {
            let mut observers = self.observers.lock();
            fire_immediately = self.notified.load(Ordering::Acquire);
            observers.push(observer.clone());
        }
        // Fire outside the lock to avoid deadlock if on_events re-enters.
        if fire_immediately && let Some(obs) = observer.upgrade() {
            obs.on_events(&Events::IN);
        }
    }

    /// Notify all registered observers. Collects them under the lock, then
    /// fires outside the lock to prevent deadlocks.
    fn notify(&self) {
        let snapshot: Vec<_>;
        {
            let observers = self.observers.lock();
            // Set notified under the lock so register_observer sees a
            // consistent state: once notified is true the observer list
            // is finalized for this notification round.
            self.notified.store(true, Ordering::Release);
            snapshot = observers
                .iter()
                .filter_map(alloc::sync::Weak::upgrade)
                .collect();
        }
        for obs in snapshot {
            obs.on_events(&Events::IN);
        }
    }
}

/// Internal per-process entry in the registry.
struct ProcessEntry<Platform: RawSyncPrimitivesProvider> {
    context: ProcessContext,
    exit_observer: Arc<ExitSubject<Platform>>,
    exited_flag: Arc<AtomicBool>,
}

/// A registry of processes with parent-child lifecycle management.
///
/// `ProcessRegistry` is parameterized on a platform type for mutex support.
pub struct ProcessRegistry<Platform: RawSyncPrimitivesProvider> {
    inner: Mutex<Platform, RegistryInner<Platform>>,
    /// Futex-like primitive: incremented on every child exit so that
    /// blocking `wait_for_child_exit_since` can unblock.
    exit_event: <Platform as crate::platform::RawMutexProvider>::RawMutex,
}

struct RegistryInner<Platform: RawSyncPrimitivesProvider> {
    processes: HashMap<ProcessId, ProcessEntry<Platform>>,
    next_pid: u32,
    /// Maximum number of processes allowed. 0 means unlimited.
    max_processes: usize,
}

#[allow(
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::new_without_default,
    clippy::result_unit_err
)]
impl<Platform: RawSyncPrimitivesProvider> ProcessRegistry<Platform> {
    /// Create a new, empty process registry.
    pub fn new() -> Self {
        Self::with_max_processes(0)
    }

    /// Create a new process registry with a maximum process count.
    /// Pass 0 for unlimited.
    pub fn with_max_processes(max_processes: usize) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                processes: HashMap::new(),
                next_pid: 1,
                max_processes,
            }),
            exit_event: <Platform as crate::platform::RawMutexProvider>::RawMutex::INIT,
        }
    }

    /// Allocate a PID and register a new process.
    ///
    /// `parent` is the parent process ID. Pass `None` to create the init
    /// process (PID 1). Only one init process is allowed.
    pub fn create_process(
        &self,
        parent: Option<ProcessId>,
    ) -> Result<ProcessId, CreateProcessError> {
        let mut inner = self.inner.lock();
        let pid = match parent {
            None => {
                // Creating init process
                let pid = ProcessId::INIT;
                if inner.processes.contains_key(&pid) {
                    return Err(CreateProcessError::InitAlreadyExists);
                }
                // Ensure next_pid is past init
                if inner.next_pid <= pid.as_u32() {
                    inner.next_pid = pid.as_u32() + 1;
                }
                pid
            }
            Some(parent_pid) => {
                if !inner.processes.contains_key(&parent_pid) {
                    return Err(CreateProcessError::NoSuchParent);
                }
                // Enforce process count limit
                if inner.max_processes > 0 && inner.processes.len() >= inner.max_processes {
                    return Err(CreateProcessError::TooManyProcesses(inner.max_processes));
                }
                let raw = inner.next_pid;
                inner.next_pid = raw
                    .checked_add(1)
                    .ok_or(CreateProcessError::PidSpaceExhausted)?;
                let pid = ProcessId(raw);
                // Register as child of parent
                inner
                    .processes
                    .get_mut(&parent_pid)
                    .unwrap()
                    .context
                    .children
                    .push(pid);
                pid
            }
        };

        let exited_flag = Arc::new(AtomicBool::new(false));
        let exit_observer = Arc::new(ExitSubject::new());

        // Determine pgid and sid: init gets its own, children inherit from parent.
        let (pgid, sid) = match parent {
            None => (pid, pid),
            Some(parent_pid) => {
                let parent_entry = inner.processes.get(&parent_pid).unwrap();
                (parent_entry.context.pgid, parent_entry.context.sid)
            }
        };

        inner.processes.insert(
            pid,
            ProcessEntry {
                context: ProcessContext {
                    id: pid,
                    parent,
                    state: ProcessState::Running,
                    pgid,
                    sid,
                    children: Vec::new(),
                },
                exit_observer,
                exited_flag,
            },
        );

        Ok(pid)
    }

    /// Ensure the next PID will be at least `min_pid`.
    /// Used to keep PIDs and TIDs in disjoint ranges when they share a namespace.
    pub fn advance_next_pid(&self, min_pid: u32) {
        let mut inner = self.inner.lock();
        if inner.next_pid < min_pid {
            inner.next_pid = min_pid;
        }
    }

    /// Remove a process that was created but never started (e.g., child setup
    /// failed after PID allocation).
    ///
    /// # Panics
    ///
    /// Panics if the process has children, is not in `Running` state, or does
    /// not exist.
    pub fn abort_process(&self, id: ProcessId) {
        let mut inner = self.inner.lock();
        let entry = inner
            .processes
            .remove(&id)
            .expect("abort_process: no such process");
        assert!(
            matches!(entry.context.state, ProcessState::Running),
            "abort_process: process not running"
        );
        assert!(
            entry.context.children.is_empty(),
            "abort_process: process has children"
        );
        // Remove from parent's children list
        if let Some(parent_pid) = entry.context.parent
            && let Some(parent) = inner.processes.get_mut(&parent_pid)
        {
            parent.context.children.retain(|&c| c != id);
        }
    }

    /// Record that a process has exited with the given status.
    ///
    /// For each orphaned child, calls `orphan_handler` so the shim can decide
    /// the reparenting policy (e.g., POSIX reparents to init).
    ///
    /// Returns `Some(ExitNotification)` if the parent is still alive,
    /// `None` otherwise.
    pub fn exit_process(
        &self,
        id: ProcessId,
        status: u32,
        mut orphan_handler: impl FnMut(ProcessId),
    ) -> Option<ExitNotification> {
        let (children, exit_observer, notification);
        {
            let mut inner = self.inner.lock();
            let entry = inner
                .processes
                .get_mut(&id)
                .expect("exit_process: no such process");
            // Idempotent: if already exited, return None without re-notifying.
            if matches!(entry.context.state, ProcessState::Exited(_)) {
                return None;
            }
            entry.context.state = ProcessState::Exited(status);
            entry.exited_flag.store(true, Ordering::Release);
            exit_observer = Arc::clone(&entry.exit_observer);
            children = entry.context.children.clone();

            // Check if parent is alive
            let parent_pid = entry.context.parent;
            notification = parent_pid.and_then(|ppid| {
                let parent = inner.processes.get(&ppid)?;
                if matches!(parent.context.state, ProcessState::Running) {
                    Some(ExitNotification {
                        parent_pid: ppid,
                        child_pid: id,
                        exit_status: status,
                    })
                } else {
                    None
                }
            });
        }
        // Wake any threads blocked in wait_for_any_child_exit.
        self.exit_event
            .underlying_atomic()
            .fetch_add(1, Ordering::Release);
        self.exit_event.wake_all();
        // All callbacks run outside the lock to prevent deadlocks.
        exit_observer.notify();
        for child_pid in children {
            orphan_handler(child_pid);
        }
        notification
    }

    /// Reparent a child process to a new parent.
    ///
    /// Updates the child's parent field, removes it from the old parent's children list,
    /// and adds it to the new parent's children list.
    ///
    /// Returns `Some(exit_status)` if the child is already a zombie (exited but not reaped),
    /// so the caller can deliver SIGCHLD to the new parent.
    pub fn reparent(&self, child: ProcessId, new_parent: ProcessId) -> Option<u32> {
        let mut inner = self.inner.lock();

        // Read child info first.
        let (old_parent, exit_status) = {
            let Some(entry) = inner.processes.get_mut(&child) else {
                return None;
            };
            let old_parent = entry.context.parent.replace(new_parent);
            let exit_status = match entry.context.state {
                ProcessState::Exited(status) => Some(status),
                _ => None,
            };
            (old_parent, exit_status)
        };

        // Remove from old parent's children list.
        if let Some(old_pid) = old_parent {
            if let Some(old_entry) = inner.processes.get_mut(&old_pid) {
                old_entry.context.children.retain(|&c| c != child);
            }
        }

        // Add to new parent's children list.
        if let Some(parent_entry) = inner.processes.get_mut(&new_parent) {
            parent_entry.context.children.push(child);
        }
        exit_status
    }

    /// Set the process group ID for a process.
    /// Returns `Ok(())` on success, `Err(())` if the process does not exist.
    pub fn set_pgid(&self, id: ProcessId, pgid: ProcessId) -> Result<(), ()> {
        let mut inner = self.inner.lock();
        let entry = inner.processes.get_mut(&id).ok_or(())?;
        entry.context.pgid = pgid;
        Ok(())
    }

    /// Create a new session: set both pgid and sid to the process's own PID.
    /// Returns `Err(())` if the process doesn't exist or is already a process group leader.
    pub fn setsid(&self, id: ProcessId) -> Result<(), ()> {
        let mut inner = self.inner.lock();
        let entry = inner.processes.get_mut(&id).ok_or(())?;
        if entry.context.pgid == id {
            return Err(()); // already a process group leader
        }
        entry.context.pgid = id;
        entry.context.sid = id;
        Ok(())
    }

    /// Collect all process IDs in the given process group.
    pub fn pids_in_group(&self, pgid: ProcessId) -> alloc::vec::Vec<ProcessId> {
        let inner = self.inner.lock();
        inner
            .processes
            .values()
            .filter(|e| e.context.pgid == pgid && matches!(e.context.state, ProcessState::Running))
            .map(|e| e.context.id)
            .collect()
    }

    /// Read process context through a closure.
    /// Returns `None` if the process does not exist.
    pub fn with_context<R>(
        &self,
        id: ProcessId,
        f: impl FnOnce(&ProcessContext) -> R,
    ) -> Option<R> {
        let inner = self.inner.lock();
        inner.processes.get(&id).map(|e| f(&e.context))
    }

    /// Returns `true` if the process exists and is in `Running` state.
    pub fn is_alive(&self, id: ProcessId) -> bool {
        let inner = self.inner.lock();
        inner
            .processes
            .get(&id)
            .is_some_and(|e| matches!(e.context.state, ProcessState::Running))
    }

    /// Get the parent PID of a process.
    pub fn get_parent(&self, id: ProcessId) -> Option<ProcessId> {
        let inner = self.inner.lock();
        inner.processes.get(&id).and_then(|e| e.context.parent)
    }

    /// Get the child PIDs of a process.
    pub fn get_children(&self, id: ProcessId) -> Option<Vec<ProcessId>> {
        let inner = self.inner.lock();
        inner.processes.get(&id).map(|e| e.context.children.clone())
    }

    /// Total number of processes in the registry (running + exited).
    pub fn process_count(&self) -> usize {
        let inner = self.inner.lock();
        inner.processes.len()
    }

    /// Remove an exited process from the table.
    ///
    /// # Panics
    ///
    /// Panics if the process is still running or does not exist.
    pub fn remove_process(&self, id: ProcessId) {
        let mut inner = self.inner.lock();
        let entry = inner
            .processes
            .remove(&id)
            .expect("remove_process: no such process");
        assert!(
            matches!(entry.context.state, ProcessState::Exited(_)),
            "remove_process: process still running"
        );
        // Remove from parent's children list
        if let Some(parent_pid) = entry.context.parent
            && let Some(parent) = inner.processes.get_mut(&parent_pid)
        {
            parent.context.children.retain(|&c| c != id);
        }
    }

    /// Non-blocking check for an exited child of `parent`.
    ///
    /// `target` selects which children to consider:
    /// - `> 0`: only the child with that specific PID
    /// - `-1`: any child
    /// - `0`: any child in the caller's process group
    /// - `< -1`: any child in process group `|target|`
    ///
    /// If a matching exited child is found, it is reaped (removed from the
    /// registry) and `Ok(Some((child_pid, exit_status)))` is returned.
    /// Returns `Ok(None)` if matching children exist but none have exited yet.
    /// Returns `Err(())` if the parent has no children matching `target`
    /// (i.e., ECHILD condition).
    pub fn try_wait(&self, parent: ProcessId, target: i32) -> Result<Option<(ProcessId, u32)>, ()> {
        let mut inner = self.inner.lock();
        let parent_entry = inner.processes.get(&parent).ok_or(())?;
        let children = parent_entry.context.children.clone();

        if children.is_empty() {
            return Err(()); // ECHILD
        }

        // Find a matching exited child
        let found = match target {
            t if t > 0 => {
                let target_pid = ProcessId(t.cast_unsigned());
                // Verify it's actually a child of parent
                if !children.contains(&target_pid) {
                    return Err(()); // ECHILD — not our child
                }
                match inner.processes.get(&target_pid) {
                    Some(e) if let ProcessState::Exited(status) = e.context.state => {
                        Some((target_pid, status))
                    }
                    _ => None,
                }
            }
            -1 => {
                // Any child
                let mut result = None;
                for &child_pid in &children {
                    if let Some(entry) = inner.processes.get(&child_pid)
                        && let ProcessState::Exited(status) = entry.context.state
                    {
                        result = Some((child_pid, status));
                        break;
                    }
                }
                result
            }
            0 => {
                // Wait for any child in the caller's process group.
                let caller_pgid = parent_entry.context.pgid;
                let mut any_match = false;
                let mut result = None;
                for &child_pid in &children {
                    if let Some(entry) = inner.processes.get(&child_pid)
                        && entry.context.pgid == caller_pgid
                    {
                        any_match = true;
                        if let ProcessState::Exited(status) = entry.context.state {
                            result = Some((child_pid, status));
                            break;
                        }
                    }
                }
                if !any_match {
                    return Err(()); // ECHILD — no children in this group
                }
                result
            }
            t if t < -1 => {
                // Wait for any child in process group |t|.
                let pgid = ProcessId(t.unsigned_abs());
                let mut any_match = false;
                let mut result = None;
                for &child_pid in &children {
                    if let Some(entry) = inner.processes.get(&child_pid)
                        && entry.context.pgid == pgid
                    {
                        any_match = true;
                        if let ProcessState::Exited(status) = entry.context.state {
                            result = Some((child_pid, status));
                            break;
                        }
                    }
                }
                if !any_match {
                    return Err(()); // ECHILD — no children in this group
                }
                result
            }
            _ => return Err(()),
        };

        // Reap the child if found
        if let Some((child_pid, _)) = found {
            // Remove child from registry. Its children should have been
            // reparented during exit_process.
            let entry = inner.processes.remove(&child_pid);
            debug_assert!(
                entry
                    .as_ref()
                    .map_or(true, |e| e.context.children.is_empty()),
                "reaped zombie still has children"
            );
            // Remove from parent's children list
            if let Some(parent) = inner.processes.get_mut(&parent) {
                parent.context.children.retain(|&c| c != child_pid);
            }
        }

        Ok(found)
    }

    /// Snapshot the current exit epoch. Used with `wait_for_child_exit_since`
    /// to implement the standard futex pattern: snapshot, check, block-on-snapshot.
    pub fn exit_epoch(&self) -> u32 {
        self.exit_event.underlying_atomic().load(Ordering::Acquire)
    }

    /// Block until a child exit occurs after the given epoch snapshot.
    /// The caller should call `exit_epoch()` BEFORE `try_wait()`, then
    /// pass the snapshot here if `try_wait` returned `Ok(None)`.
    pub fn wait_for_child_exit_since(&self, epoch: u32) {
        let _ = self.exit_event.block(epoch);
    }

    /// Block until any child exit occurs (or return immediately if one has
    /// happened since the last call). Used by blocking wait4.
    pub fn wait_for_any_child_exit(&self) {
        let epoch = self.exit_event.underlying_atomic().load(Ordering::Acquire);
        let _ = self.exit_event.block(epoch);
    }

    /// Get exit observers for all children of `parent` matching `target`.
    /// Used by blocking wait to know when to re-check.
    pub fn child_exit_observers(
        &self,
        parent: ProcessId,
        target: i32,
    ) -> Vec<ProcessExitObserver<Platform>> {
        let inner = self.inner.lock();
        let Some(parent_entry) = inner.processes.get(&parent) else {
            return Vec::new();
        };
        let children = &parent_entry.context.children;
        let pids: Vec<ProcessId> = match target {
            t if t > 0 => {
                let pid = ProcessId(t.cast_unsigned());
                if children.contains(&pid) {
                    alloc::vec![pid]
                } else {
                    Vec::new()
                }
            }
            -1 => children.clone(),
            _ => Vec::new(),
        };
        pids.iter()
            .filter_map(|pid| {
                let entry = inner.processes.get(pid)?;
                Some(ProcessExitObserver {
                    exited: Arc::clone(&entry.exited_flag),
                    observer: Arc::clone(&entry.exit_observer),
                })
            })
            .collect()
    }

    /// Obtain a shared exit-observation handle for the given process.
    pub fn exit_observer(&self, id: ProcessId) -> Option<ProcessExitObserver<Platform>> {
        let inner = self.inner.lock();
        let entry = inner.processes.get(&id)?;
        Some(ProcessExitObserver {
            exited: Arc::clone(&entry.exited_flag),
            observer: Arc::clone(&entry.exit_observer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockPlatform;

    type Registry = ProcessRegistry<MockPlatform>;

    fn new_registry() -> Registry {
        Registry::new()
    }

    #[test]
    fn test_create_init_process() {
        let registry = new_registry();
        let pid = registry.create_process(None).unwrap();
        assert_eq!(pid, ProcessId::INIT);
        assert!(registry.is_alive(pid));
        assert_eq!(registry.get_parent(pid), None);
    }

    #[test]
    fn test_create_child_process() {
        let registry = new_registry();
        let init = registry.create_process(None).unwrap();
        let child = registry.create_process(Some(init)).unwrap();
        assert_ne!(init, child);
        assert!(registry.is_alive(child));
        assert_eq!(registry.get_parent(child), Some(init));
        assert_eq!(registry.get_children(init), Some(alloc::vec![child]));
    }

    #[test]
    fn test_exit_process() {
        let registry = new_registry();
        let init = registry.create_process(None).unwrap();
        let child = registry.create_process(Some(init)).unwrap();

        let notif = registry.exit_process(child, 42, |_| {});
        assert!(notif.is_some());
        let notif = notif.unwrap();
        assert_eq!(notif.parent_pid, init);
        assert_eq!(notif.child_pid, child);
        assert_eq!(notif.exit_status, 42);

        assert!(!registry.is_alive(child));
        registry.remove_process(child);
        assert_eq!(registry.get_children(init), Some(alloc::vec![]));
    }

    #[test]
    fn test_abort_process() {
        let registry = new_registry();
        let init = registry.create_process(None).unwrap();
        let child = registry.create_process(Some(init)).unwrap();
        registry.abort_process(child);
        assert_eq!(registry.get_children(init), Some(alloc::vec![]));
    }

    #[test]
    fn test_duplicate_init_rejected() {
        let registry = new_registry();
        registry.create_process(None).unwrap();
        assert!(matches!(
            registry.create_process(None),
            Err(CreateProcessError::InitAlreadyExists)
        ));
    }

    #[test]
    fn test_exit_observer() {
        let registry = new_registry();
        let init = registry.create_process(None).unwrap();
        let child = registry.create_process(Some(init)).unwrap();

        let observer = registry.exit_observer(child).unwrap();
        assert!(!observer.exited.load(Ordering::Acquire));

        registry.exit_process(child, 0, |_| {});
        assert!(observer.exited.load(Ordering::Acquire));
    }
}
