// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Container state management for OCI lifecycle.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Container status per OCI runtime spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Container is being created
    Creating,
    /// Container has been created but not started
    Created,
    /// Container is running
    Running,
    /// Container is paused (SIGSTOP)
    Paused,
    /// Container has exited
    Stopped,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Creating => write!(f, "creating"),
            Status::Created => write!(f, "created"),
            Status::Running => write!(f, "running"),
            Status::Paused => write!(f, "paused"),
            Status::Stopped => write!(f, "stopped"),
        }
    }
}

/// Container state per OCI runtime spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    /// OCI version
    #[serde(rename = "ociVersion")]
    pub oci_version: String,

    /// Container ID
    pub id: String,

    /// Current status
    pub status: Status,

    /// PID of the container's init process (if running)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Path to the OCI bundle
    pub bundle: PathBuf,

    /// Optional annotations
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub annotations: std::collections::HashMap<String, String>,

    /// Exit code of the container process (set when stopped)
    #[serde(default, rename = "exitCode", skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl ContainerState {
    /// Create a new container state.
    pub fn new(id: String, bundle: PathBuf) -> Self {
        Self {
            oci_version: "1.0.0".to_string(),
            id,
            status: Status::Creating,
            pid: None,
            bundle,
            annotations: std::collections::HashMap::new(),
            exit_code: None,
        }
    }
}

/// Manages container state on disk.
pub struct StateManager {
    root: PathBuf,
}

impl StateManager {
    /// Create a new state manager with the given root directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Get the state directory for a container.
    pub fn container_dir(&self, id: &str) -> PathBuf {
        self.root.join("containers").join(id)
    }

    /// Get the state file path for a container.
    fn state_file(&self, id: &str) -> PathBuf {
        self.container_dir(id).join("state.json")
    }

    /// Get the sync pipe path for a container.
    /// Uses /tmp with truncated ID to avoid Unix socket path length limits (108 chars).
    pub fn sync_pipe(&self, id: &str) -> PathBuf {
        // Truncate ID to 16 chars to keep path short
        let short_id = if id.len() > 16 { &id[..16] } else { id };
        PathBuf::from(format!("/tmp/litebox-{short_id}.sock"))
    }

    /// Check if a container exists.
    pub fn exists(&self, id: &str) -> bool {
        self.state_file(id).exists()
    }

    /// List all container IDs.
    pub fn list(&self) -> Result<Vec<String>> {
        let containers_dir = self.root.join("containers");
        if !containers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut ids = Vec::new();
        for entry in fs::read_dir(&containers_dir)
            .with_context(|| format!("failed to read {}", containers_dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                ids.push(name.to_string());
            }
        }
        Ok(ids)
    }

    /// Create state directory for a new container.
    pub fn create_dir(&self, id: &str) -> Result<PathBuf> {
        let dir = self.container_dir(id);
        if dir.exists() {
            anyhow::bail!("container {id} already exists");
        }
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create state directory: {}", dir.display()))?;
        Ok(dir)
    }

    /// Save container state to disk.
    pub fn save(&self, state: &ContainerState) -> Result<()> {
        let path = self.state_file(&state.id);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(state)?;
        fs::write(&path, json)
            .with_context(|| format!("failed to write state to {}", path.display()))?;
        Ok(())
    }

    /// Load container state from disk.
    pub fn load(&self, id: &str) -> Result<ContainerState> {
        let path = self.state_file(id);
        let json =
            fs::read_to_string(&path).with_context(|| format!("container {id} not found"))?;
        let state: ContainerState = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse state for container {id}"))?;
        Ok(state)
    }

    /// Update container state on disk.
    pub fn update<F>(&self, id: &str, f: F) -> Result<ContainerState>
    where
        F: FnOnce(&mut ContainerState),
    {
        let mut state = self.load(id)?;
        f(&mut state);
        self.save(&state)?;
        Ok(state)
    }

    /// Delete container state directory.
    pub fn delete(&self, id: &str) -> Result<()> {
        let dir = self.container_dir(id);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to remove state directory: {}", dir.display()))?;
        }
        Ok(())
    }

    /// Check if the container process is still running.
    pub fn is_process_alive(pid: u32) -> bool {
        // Send signal 0 to check if process exists
        unsafe { libc::kill(pid.cast_signed(), 0) == 0 }
    }

    /// Refresh container state by checking if process is still alive.
    /// If the process has exited, captures the exit code.
    pub fn refresh_state(&self, id: &str) -> Result<ContainerState> {
        let mut state = self.load(id)?;

        if matches!(state.status, Status::Running | Status::Paused)
            && let Some(pid) = state.pid
            && !Self::is_process_alive(pid)
        {
            state.status = Status::Stopped;
            // Try waitpid first (works if we're the parent)
            if let Some(code) = Self::try_wait_exit_code(pid) {
                state.exit_code = Some(code);
            }
            self.save(&state)?;
        }

        Ok(state)
    }

    /// Try to collect exit code from a child process using `waitpid` with `WNOHANG`.
    /// Returns `Some(exit_code)` if the process has exited and we are its parent,
    /// `None` if still running or not our child.
    pub fn try_wait_exit_code(pid: u32) -> Option<i32> {
        let mut status: i32 = 0;
        // SAFETY: waitpid with WNOHANG is a standard, safe Linux syscall.
        let ret = unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, libc::WNOHANG) };
        if ret > 0 {
            if libc::WIFEXITED(status) {
                Some(libc::WEXITSTATUS(status))
            } else if libc::WIFSIGNALED(status) {
                // Killed by signal: convention is 128 + signal number
                Some(128 + libc::WTERMSIG(status))
            } else {
                Some(-1)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_temp_manager() -> (TempDir, StateManager) {
        let temp_dir = TempDir::new().unwrap();
        let manager = StateManager::new(temp_dir.path().to_path_buf());
        (temp_dir, manager)
    }

    #[test]
    fn test_status_display() {
        assert_eq!(Status::Creating.to_string(), "creating");
        assert_eq!(Status::Created.to_string(), "created");
        assert_eq!(Status::Running.to_string(), "running");
        assert_eq!(Status::Paused.to_string(), "paused");
        assert_eq!(Status::Stopped.to_string(), "stopped");
    }

    #[test]
    fn test_status_serde() {
        // Serialize
        assert_eq!(
            serde_json::to_string(&Status::Creating).unwrap(),
            "\"creating\""
        );
        assert_eq!(
            serde_json::to_string(&Status::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&Status::Paused).unwrap(),
            "\"paused\""
        );

        // Deserialize
        assert_eq!(
            serde_json::from_str::<Status>("\"created\"").unwrap(),
            Status::Created
        );
        assert_eq!(
            serde_json::from_str::<Status>("\"stopped\"").unwrap(),
            Status::Stopped
        );
        assert_eq!(
            serde_json::from_str::<Status>("\"paused\"").unwrap(),
            Status::Paused
        );
    }

    #[test]
    fn test_container_state_new() {
        let state = ContainerState::new("test-id".to_string(), PathBuf::from("/tmp/bundle"));

        assert_eq!(state.oci_version, "1.0.0");
        assert_eq!(state.id, "test-id");
        assert_eq!(state.status, Status::Creating);
        assert!(state.pid.is_none());
        assert_eq!(state.bundle, PathBuf::from("/tmp/bundle"));
        assert!(state.annotations.is_empty());
        assert!(state.exit_code.is_none());
    }

    #[test]
    fn test_state_manager_paths() {
        let (_temp, manager) = create_temp_manager();

        assert!(manager.container_dir("foo").ends_with("containers/foo"));
        // sync_pipe uses /tmp to avoid Unix socket path length limits
        let sync_path = manager.sync_pipe("foo");
        let sync_str = sync_path.to_string_lossy();
        assert!(
            sync_str.starts_with("/tmp/litebox-"),
            "Expected sync_pipe to start with /tmp/litebox-, got: {sync_str}"
        );
        assert!(
            sync_str.contains("foo"),
            "Expected sync_pipe to contain 'foo', got: {sync_str}"
        );
    }

    #[test]
    fn test_state_manager_create_and_exists() {
        let (_temp, manager) = create_temp_manager();

        assert!(!manager.exists("test-container"));

        manager.create_dir("test-container").unwrap();

        // Directory exists but state file doesn't yet
        assert!(!manager.exists("test-container"));

        // Save state to create the file
        let state = ContainerState::new("test-container".to_string(), PathBuf::from("/bundle"));
        manager.save(&state).unwrap();

        assert!(manager.exists("test-container"));
    }

    #[test]
    fn test_state_manager_create_duplicate_fails() {
        let (_temp, manager) = create_temp_manager();

        manager.create_dir("test-container").unwrap();
        let result = manager.create_dir("test-container");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_state_manager_save_and_load() {
        let (_temp, manager) = create_temp_manager();

        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/tmp/bundle"));
        state.status = Status::Running;
        state.pid = Some(12345);
        state
            .annotations
            .insert("key".to_string(), "value".to_string());

        manager.save(&state).unwrap();
        let loaded = manager.load("test-id").unwrap();

        assert_eq!(loaded.id, "test-id");
        assert_eq!(loaded.status, Status::Running);
        assert_eq!(loaded.pid, Some(12345));
        assert_eq!(loaded.bundle, PathBuf::from("/tmp/bundle"));
        assert_eq!(loaded.annotations.get("key").unwrap(), "value");
    }

    #[test]
    fn test_state_manager_load_not_found() {
        let (_temp, manager) = create_temp_manager();

        let result = manager.load("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_state_manager_update() {
        let (_temp, manager) = create_temp_manager();

        let state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        manager.save(&state).unwrap();

        let updated = manager
            .update("test-id", |s| {
                s.status = Status::Running;
                s.pid = Some(999);
            })
            .unwrap();

        assert_eq!(updated.status, Status::Running);
        assert_eq!(updated.pid, Some(999));

        // Verify persisted
        let loaded = manager.load("test-id").unwrap();
        assert_eq!(loaded.status, Status::Running);
    }

    #[test]
    fn test_state_manager_delete() {
        let (_temp, manager) = create_temp_manager();

        manager.create_dir("test-container").unwrap();
        let state = ContainerState::new("test-container".to_string(), PathBuf::from("/bundle"));
        manager.save(&state).unwrap();

        assert!(manager.exists("test-container"));

        manager.delete("test-container").unwrap();

        assert!(!manager.exists("test-container"));
        assert!(!manager.container_dir("test-container").exists());
    }

    #[test]
    fn test_state_manager_delete_nonexistent_ok() {
        let (_temp, manager) = create_temp_manager();

        // Should not error on nonexistent container
        manager.delete("nonexistent").unwrap();
    }

    #[test]
    fn test_state_manager_list_empty() {
        let (_temp, manager) = create_temp_manager();

        let ids = manager.list().unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_state_manager_list() {
        let (_temp, manager) = create_temp_manager();

        manager.create_dir("container-a").unwrap();
        manager.create_dir("container-b").unwrap();
        manager.create_dir("container-c").unwrap();

        let mut ids = manager.list().unwrap();
        ids.sort();

        assert_eq!(ids, vec!["container-a", "container-b", "container-c"]);
    }

    #[test]
    fn test_is_process_alive() {
        // Current process should be alive
        let pid = std::process::id();
        assert!(StateManager::is_process_alive(pid));

        // PID 0 (kernel) check - typically not accessible
        // PID that almost certainly doesn't exist
        assert!(!StateManager::is_process_alive(u32::MAX - 1000));
    }

    #[test]
    fn test_refresh_state_running_process_dead() {
        let (_temp, manager) = create_temp_manager();

        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        state.status = Status::Running;
        state.pid = Some(u32::MAX - 1000); // Non-existent PID
        manager.save(&state).unwrap();

        let refreshed = manager.refresh_state("test-id").unwrap();

        assert_eq!(refreshed.status, Status::Stopped);
    }

    #[test]
    fn test_refresh_state_running_process_alive() {
        let (_temp, manager) = create_temp_manager();

        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        state.status = Status::Running;
        state.pid = Some(std::process::id()); // Current process is alive
        manager.save(&state).unwrap();

        let refreshed = manager.refresh_state("test-id").unwrap();

        assert_eq!(refreshed.status, Status::Running);
    }

    #[test]
    fn test_refresh_state_not_running() {
        let (_temp, manager) = create_temp_manager();

        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        state.status = Status::Created;
        state.pid = Some(u32::MAX - 1000);
        manager.save(&state).unwrap();

        let refreshed = manager.refresh_state("test-id").unwrap();

        // Status unchanged because it wasn't Running
        assert_eq!(refreshed.status, Status::Created);
    }

    #[test]
    fn test_container_state_json_format() {
        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        state.status = Status::Running;
        state.pid = Some(12345);

        let json = serde_json::to_string_pretty(&state).unwrap();

        // Verify OCI-compliant field names
        assert!(json.contains("\"ociVersion\""));
        assert!(json.contains("\"1.0.0\""));
        assert!(json.contains("\"status\": \"running\""));
        assert!(json.contains("\"pid\": 12345"));

        // Annotations and exitCode should be omitted when empty/none
        assert!(!json.contains("annotations"));
        assert!(!json.contains("exitCode"));
    }

    #[test]
    fn test_exit_code_serialization() {
        let mut state = ContainerState::new("test-id".to_string(), PathBuf::from("/bundle"));
        state.status = Status::Stopped;
        state.exit_code = Some(0);

        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"exitCode\": 0"));

        // Non-zero exit code
        state.exit_code = Some(137);
        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"exitCode\": 137"));
    }

    #[test]
    fn test_exit_code_deserialization() {
        let json = r#"{
            "ociVersion": "1.0.0",
            "id": "test",
            "status": "stopped",
            "bundle": "/bundle",
            "exitCode": 42
        }"#;
        let state: ContainerState = serde_json::from_str(json).unwrap();
        assert_eq!(state.exit_code, Some(42));

        // Without exitCode (backward compatible)
        let json_no_exit = r#"{
            "ociVersion": "1.0.0",
            "id": "test",
            "status": "stopped",
            "bundle": "/bundle"
        }"#;
        let state: ContainerState = serde_json::from_str(json_no_exit).unwrap();
        assert_eq!(state.exit_code, None);
    }

    #[test]
    fn test_try_wait_exit_code() {
        // Spawn a real child process that exits with code 42
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 42"])
            .spawn()
            .unwrap();
        let pid = child.id();

        // Wait for child to exit
        std::thread::sleep(std::time::Duration::from_millis(200));

        let code = StateManager::try_wait_exit_code(pid);
        assert_eq!(code, Some(42));
        // Reap the child to avoid zombie.
        let _ = child.wait();
    }

    #[test]
    fn test_try_wait_exit_code_zero() {
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = child.id();

        std::thread::sleep(std::time::Duration::from_millis(200));

        let code = StateManager::try_wait_exit_code(pid);
        assert_eq!(code, Some(0));
        let _ = child.wait();
    }

    #[test]
    fn test_signal_exit_code() {
        // Convention: signal death = 128 + signal number
        assert_eq!(128 + 9, 137); // SIGKILL
        assert_eq!(128 + 15, 143); // SIGTERM
    }
}
