// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI container lifecycle management.
//!
//! Implements the OCI runtime lifecycle: create, start, state, kill, delete.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use oci_spec::runtime::Hook;

use crate::state::{ContainerState, StateManager, Status};

/// Set up a PTY and send the master fd over a console socket.
///
/// Creates a new pseudoterminal pair. Sends the master fd to the
/// console-socket via `SCM_RIGHTS` (as runc does per OCI spec).
/// Returns the slave fd which should be used for container stdio.
fn setup_console_socket(console_socket_path: &Path) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[repr(C)]
    struct CmsgFd {
        hdr: libc::cmsghdr,
        fd: i32,
    }

    // Open a new PTY master via posix_openpt
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_fd < 0 {
        anyhow::bail!("posix_openpt failed: {}", std::io::Error::last_os_error());
    }
    // SAFETY: master_fd is a valid fd returned by posix_openpt
    let master = unsafe { OwnedFd::from_raw_fd(master_fd) };

    if unsafe { libc::grantpt(master_fd) } != 0 {
        anyhow::bail!("grantpt failed: {}", std::io::Error::last_os_error());
    }
    if unsafe { libc::unlockpt(master_fd) } != 0 {
        anyhow::bail!("unlockpt failed: {}", std::io::Error::last_os_error());
    }

    // Get slave path
    let slave_name = unsafe { libc::ptsname(master_fd) };
    if slave_name.is_null() {
        anyhow::bail!("ptsname failed: {}", std::io::Error::last_os_error());
    }
    // SAFETY: ptsname returned a valid C string
    let slave_path = unsafe { std::ffi::CStr::from_ptr(slave_name) };
    let slave_fd = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR) };
    if slave_fd < 0 {
        anyhow::bail!(
            "failed to open PTY slave: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: slave_fd is a valid fd returned by open
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };

    // Connect to the console-socket and send master fd via SCM_RIGHTS
    let sock = UnixStream::connect(console_socket_path).with_context(|| {
        format!(
            "failed to connect to console-socket: {}",
            console_socket_path.display()
        )
    })?;

    // Send master fd using sendmsg + SCM_RIGHTS
    let sock_fd = sock.as_raw_fd();
    let data: [u8; 1] = [0];
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    #[allow(clippy::cast_possible_truncation)]
    let mut cmsg_buf = CmsgFd {
        hdr: libc::cmsghdr {
            cmsg_len: unsafe { libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) } as _,
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        },
        fd: master.as_raw_fd(),
    };
    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: (&raw const iov).cast_mut(),
        msg_iovlen: 1,
        msg_control: (&raw mut cmsg_buf).cast::<libc::c_void>(),
        msg_controllen: std::mem::size_of::<CmsgFd>(),
        msg_flags: 0,
    };
    let ret = unsafe { libc::sendmsg(sock_fd, &raw const msg, 0) };
    if ret < 0 {
        anyhow::bail!(
            "sendmsg (SCM_RIGHTS) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Close the master fd and socket — orchestrator now owns the master
    drop(master);
    drop(sock);

    Ok(slave)
}

/// Check if the OCI spec requests a new network namespace (type=network, no path).
/// When true, the child process should unshare into a new netns so that container
/// managers can apply CNI plugins to the child's /proc/<pid>/ns/net.
fn should_unshare_netns(spec: &oci_spec::runtime::Spec) -> bool {
    use oci_spec::runtime::LinuxNamespaceType;
    spec.linux()
        .as_ref()
        .and_then(|l| l.namespaces().as_ref())
        .is_some_and(|namespaces| {
            namespaces
                .iter()
                .any(|ns| ns.typ() == LinuxNamespaceType::Network && ns.path().is_none())
        })
}

/// Execute a list of OCI lifecycle hooks.
///
/// Each hook receives the container state JSON on stdin. Hooks are executed
/// sequentially in the order specified. If a hook fails, subsequent hooks
/// are skipped and an error is returned.
fn run_hooks(hooks: &[Hook], state: &ContainerState, label: &str) -> Result<()> {
    let state_json =
        serde_json::to_string(state).context("failed to serialize container state for hook")?;

    for hook in hooks {
        let path = hook.path();
        tracing::info!(hook = %path.display(), phase = label, "executing OCI hook");

        let mut cmd = std::process::Command::new(path);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit());

        if let Some(args) = hook.args() {
            // OCI spec: args[0] is the binary name (like execv), skip path and use args as-is
            cmd.args(args.iter().skip(1));
        }
        if let Some(env) = hook.env() {
            for e in env {
                if let Some((k, v)) = e.split_once('=') {
                    cmd.env(k, v);
                }
            }
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to execute {label} hook: {}", path.display()))?;

        // Write state JSON to hook's stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(state_json.as_bytes());
        }

        let timeout = hook
            .timeout()
            .filter(|&t| t > 0)
            .map(|t| Duration::from_secs(t.unsigned_abs()));

        let status = if let Some(timeout) = timeout {
            // Poll with try_wait to implement timeout without adding a dependency
            let deadline = std::time::Instant::now() + timeout;
            loop {
                match child.try_wait() {
                    Ok(Some(s)) => break s,
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let _ = child.wait();
                            anyhow::bail!(
                                "{label} hook {} timed out after {}s",
                                path.display(),
                                timeout.as_secs()
                            );
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        anyhow::bail!("{label} hook {} wait failed: {e}", path.display());
                    }
                }
            }
        } else {
            child
                .wait()
                .with_context(|| format!("{label} hook {} wait failed", path.display()))?
        };

        if !status.success() {
            anyhow::bail!(
                "{label} hook {} failed with exit status: {status}",
                path.display()
            );
        }

        tracing::debug!(hook = %path.display(), phase = label, "hook completed successfully");
    }

    Ok(())
}

/// OCI lifecycle manager.
pub struct Lifecycle {
    state_manager: StateManager,
}

impl Lifecycle {
    /// Create a new lifecycle manager.
    #[must_use]
    pub fn new(state_manager: StateManager) -> Self {
        Self { state_manager }
    }

    /// Create a container without starting it.
    ///
    /// This spawns a child process that waits for the start signal via a Unix socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundle or config.json is invalid, the container
    /// already exists, forking fails, or a `createRuntime`/`createContainer` hook fails.
    ///
    /// # Panics
    ///
    /// This function may panic in the child process if:
    /// - Failed to bind the sync socket
    /// - Failed to signal ready to parent
    /// - Failed to accept start connection
    /// - Failed to read start signal
    #[allow(clippy::too_many_lines)]
    pub fn create(
        &self,
        id: &str,
        bundle: &Path,
        console_socket: Option<&Path>,
        extra_run_args: &[String],
    ) -> Result<ContainerState> {
        // Validate bundle
        let bundle = bundle
            .canonicalize()
            .with_context(|| format!("bundle not found: {}", bundle.display()))?;

        let config_path = bundle.join("config.json");
        if !config_path.exists() {
            anyhow::bail!("config.json not found in bundle: {}", bundle.display());
        }

        // Check if container already exists
        if self.state_manager.exists(id) {
            anyhow::bail!("container {id} already exists");
        }

        // Parse OCI spec for hooks
        let spec: oci_spec::runtime::Spec = serde_json::from_reader(
            fs::File::open(&config_path).context("failed to open config.json")?,
        )
        .context("failed to parse config.json")?;

        // Create state directory
        let state_dir = self.state_manager.create_dir(id)?;

        // Create a pair of connected sockets for parent-child sync
        let (parent_sock, child_sock) =
            UnixStream::pair().context("failed to create socket pair")?;

        // Create sync socket that the child will listen on for start command
        let sync_path = self.state_manager.sync_pipe(id);

        // Get path to current executable
        let exe = std::env::current_exe().context("failed to get current executable")?;

        // Fork using nix for proper control
        match unsafe { nix::unistd::fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Parent process
                drop(child_sock); // Close child's end
                let pid = child.as_raw().cast_unsigned();

                // Wait for child to signal it's ready
                let mut parent_sock = parent_sock;
                let mut buf = [0u8; 1];
                parent_sock
                    .read_exact(&mut buf)
                    .context("failed to read sync from child")?;

                if buf[0] != b'R' {
                    anyhow::bail!("child process failed to initialize");
                }

                // Save state
                let mut state = ContainerState::new(id.to_string(), bundle);
                state.status = Status::Created;
                state.pid = Some(pid);
                self.state_manager.save(&state)?;

                // Run createRuntime hooks (OCI spec: after container created, in runtime ns)
                if let Some(hooks) = spec.hooks() {
                    if let Some(cr_hooks) = hooks.create_runtime()
                        && let Err(e) = run_hooks(cr_hooks, &state, "createRuntime")
                    {
                        tracing::warn!(error = %e, "createRuntime hook failed");
                        return Err(e);
                    }
                    // createContainer hooks run in container ns; since litebox shares
                    // the address space, we execute them here as well.
                    if let Some(cc_hooks) = hooks.create_container()
                        && let Err(e) = run_hooks(cc_hooks, &state, "createContainer")
                    {
                        tracing::warn!(error = %e, "createContainer hook failed");
                        return Err(e);
                    }
                }

                Ok(state)
            }
            Ok(nix::unistd::ForkResult::Child) => {
                // Child process
                drop(parent_sock); // Close parent's end
                let mut child_sock = child_sock;

                // If the OCI spec requests a new network namespace (no path), unshare
                // into one so that container managers (e.g., ctr --cni) can apply CNI
                // plugins to our netns via /proc/<pid>/ns/net.
                if let Ok(spec_data) = fs::read(&config_path)
                    && let Ok(spec) = serde_json::from_slice::<oci_spec::runtime::Spec>(&spec_data)
                    && should_unshare_netns(&spec)
                {
                    // SAFETY: unshare is a standard Linux syscall.
                    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                    if ret == 0 {
                        // Bring up loopback in the new netns
                        let _ = std::process::Command::new("ip")
                            .args(["link", "set", "lo", "up"])
                            .status();
                    }
                }

                // Create a listener socket that start() will connect to
                let listener =
                    UnixListener::bind(&sync_path).expect("child: failed to bind sync socket");

                // Set up PTY before signaling ready — orchestrators (conmon, containerd)
                // expect the console-socket connection to complete during `create`.
                if let Some(cs_path) = console_socket {
                    use std::os::fd::AsRawFd;
                    match setup_console_socket(cs_path) {
                        Ok(slave_fd) => {
                            let raw = slave_fd.as_raw_fd();
                            // Dup slave fd onto stdin/stdout/stderr
                            unsafe {
                                libc::setsid();
                                libc::dup2(raw, 0); // stdin
                                libc::dup2(raw, 1); // stdout
                                libc::dup2(raw, 2); // stderr
                                libc::ioctl(raw, libc::TIOCSCTTY, 0);
                            }
                            drop(slave_fd); // Close the original fd (duped onto 0/1/2)
                        }
                        Err(e) => {
                            eprintln!("child: console-socket setup failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }

                // Signal parent we're ready
                child_sock
                    .write_all(b"R")
                    .expect("child: failed to signal ready");
                drop(child_sock); // Done with parent sync

                // Wait for start command to connect
                let (mut stream, _) = listener
                    .accept()
                    .expect("child: failed to accept start connection");

                // Wait for start signal
                let mut buf = [0u8; 1];
                stream
                    .read_exact(&mut buf)
                    .expect("child: failed to read start signal");

                if buf[0] == b'S' {
                    // Clean up listener before exec
                    drop(listener);
                    let _ = fs::remove_file(&sync_path);

                    // Execute the container
                    let mut cmd = exec::Command::new(&exe);
                    cmd.arg("run").arg("--bundle").arg(&bundle);
                    for arg in extra_run_args {
                        cmd.arg(arg);
                    }
                    cmd.arg(id);
                    let err = cmd.exec();

                    eprintln!("child: exec failed: {err}");
                    std::process::exit(1);
                } else {
                    // Killed before start
                    std::process::exit(0);
                }
            }
            Err(e) => {
                // Clean up state directory on fork failure
                let _ = fs::remove_dir_all(&state_dir);
                anyhow::bail!("fork failed: {e}");
            }
        }
    }

    /// Start a created container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not in `Created` state, the sync
    /// socket connection fails, or a `prestart`/`startContainer` hook fails.
    pub fn start(&self, id: &str) -> Result<ContainerState> {
        let state = self.state_manager.load(id)?;

        if state.status != Status::Created {
            anyhow::bail!(
                "cannot start container {}: status is {} (expected created)",
                id,
                state.status
            );
        }

        // Parse OCI spec for hooks
        let config_path = state.bundle.join("config.json");
        let spec_hooks: Option<oci_spec::runtime::Hooks> = if config_path.exists() {
            fs::File::open(&config_path)
                .ok()
                .and_then(|f| serde_json::from_reader::<_, oci_spec::runtime::Spec>(f).ok())
                .and_then(|s| s.hooks().clone())
        } else {
            None
        };

        // Run prestart hooks (deprecated, but still supported per spec)
        #[allow(deprecated)]
        if let Some(ref hooks) = spec_hooks {
            if let Some(prestart) = hooks.prestart() {
                run_hooks(prestart, &state, "prestart")?;
            }
            // startContainer hooks run in container namespace; litebox shares
            // the address space, so we execute them here before signaling start.
            if let Some(sc_hooks) = hooks.start_container() {
                run_hooks(sc_hooks, &state, "startContainer")?;
            }
        }

        // Connect to the child's sync socket and signal it to start
        let sync_path = self.state_manager.sync_pipe(id);
        let mut stream = UnixStream::connect(&sync_path).with_context(|| {
            format!(
                "failed to connect to container sync socket at {}. \
                 The container process may have exited unexpectedly. \
                 Try deleting and recreating the container.",
                sync_path.display()
            )
        })?;

        stream
            .write_all(b"S")
            .context("failed to send start signal")?;
        drop(stream);

        // Update state
        let state = self.state_manager.update(id, |s| {
            s.status = Status::Running;
        })?;

        // Run poststart hooks (OCI spec: after container process started, in runtime ns)
        if let Some(ref hooks) = spec_hooks
            && let Some(poststart) = hooks.poststart()
        {
            // poststart hooks are best-effort per OCI spec — log but don't fail
            if let Err(e) = run_hooks(poststart, &state, "poststart") {
                tracing::warn!(error = %e, "poststart hook failed (non-fatal)");
            }
        }

        Ok(state)
    }

    /// Get the state of a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or state cannot be read.
    pub fn state(&self, id: &str) -> Result<ContainerState> {
        self.state_manager.refresh_state(id)
    }

    /// Send a signal to a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found, already stopped, or
    /// the signal cannot be delivered.
    pub fn kill(&self, id: &str, signal: i32) -> Result<()> {
        let state = self.state_manager.refresh_state(id)?;

        if state.status == Status::Stopped {
            anyhow::bail!("container {id} is already stopped");
        }

        let pid = state.pid.context("container has no PID")?;

        let result = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid.cast_signed()),
            nix::sys::signal::Signal::try_from(signal).ok(),
        );

        if let Err(e) = result {
            anyhow::bail!("failed to send signal {signal} to process {pid}: {e}");
        }

        // Check if process exited and capture exit code
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !StateManager::is_process_alive(pid) {
            let exit_code = StateManager::try_wait_exit_code(pid);
            self.state_manager.update(id, |s| {
                s.status = Status::Stopped;
                s.exit_code = exit_code;
            })?;
        }

        Ok(())
    }

    /// Delete a container.
    ///
    /// # Errors
    ///
    /// Returns an error if the container is not found or is still running
    /// (unless `force` is true).
    pub fn delete(&self, id: &str, force: bool) -> Result<()> {
        let state = self.state_manager.refresh_state(id)?;

        match state.status {
            Status::Stopped => {
                // OK to delete
            }
            Status::Created => {
                // Kill the waiting process first
                if let Some(pid) = state.pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid.cast_signed()),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            Status::Running if force => {
                // Force kill
                if let Some(pid) = state.pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid.cast_signed()),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            _ => {
                anyhow::bail!(
                    "cannot delete container {}: status is {} (must be stopped, or use --force)",
                    id,
                    state.status
                );
            }
        }

        // Run poststop hooks (OCI spec: after container exits, in runtime ns)
        let config_path = state.bundle.join("config.json");
        if let Ok(f) = fs::File::open(&config_path)
            && let Ok(spec) = serde_json::from_reader::<_, oci_spec::runtime::Spec>(f)
            && let Some(hooks) = spec.hooks()
            && let Some(poststop) = hooks.poststop()
        {
            // poststop hooks are best-effort per OCI spec
            if let Err(e) = run_hooks(poststop, &state, "poststop") {
                tracing::warn!(error = %e, "poststop hook failed (non-fatal)");
            }
        }

        self.state_manager.delete(id)?;
        Ok(())
    }

    /// List all containers.
    ///
    /// # Errors
    ///
    /// Returns an error if the state directory cannot be read.
    pub fn list(&self) -> Result<Vec<ContainerState>> {
        let ids = self.state_manager.list()?;
        let mut states = Vec::new();
        for id in ids {
            match self.state_manager.refresh_state(&id) {
                Ok(state) => states.push(state),
                Err(e) => {
                    tracing::warn!(container = %id, error = %e, "failed to load container state");
                }
            }
        }
        Ok(states)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateManager;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_temp_lifecycle() -> (TempDir, Lifecycle) {
        let temp_dir = TempDir::new().unwrap();
        let state_manager = StateManager::new(temp_dir.path().to_path_buf());
        let lifecycle = Lifecycle::new(state_manager);
        (temp_dir, lifecycle)
    }

    fn create_valid_bundle(temp_dir: &TempDir) -> PathBuf {
        let bundle_dir = temp_dir.path().join("bundle");
        fs::create_dir_all(&bundle_dir).unwrap();

        // Create minimal config.json
        let config = r#"{
            "ociVersion": "1.0.0",
            "root": { "path": "rootfs" },
            "process": {
                "args": ["/bin/echo", "hello"],
                "cwd": "/"
            }
        }"#;
        fs::write(bundle_dir.join("config.json"), config).unwrap();

        // Create rootfs directory
        fs::create_dir_all(bundle_dir.join("rootfs")).unwrap();

        bundle_dir
    }

    #[test]
    fn test_lifecycle_new() {
        let temp_dir = TempDir::new().unwrap();
        let state_manager = StateManager::new(temp_dir.path().to_path_buf());
        let _lifecycle = Lifecycle::new(state_manager);
        // Constructor should work without error
    }

    #[test]
    fn test_create_bundle_not_found() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let result = lifecycle.create("test-id", Path::new("/nonexistent/bundle"), None, &[]);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bundle not found"));
    }

    #[test]
    fn test_create_config_not_found() {
        let (temp, lifecycle) = create_temp_lifecycle();

        // Create bundle dir without config.json
        let bundle_dir = temp.path().join("bundle");
        fs::create_dir_all(&bundle_dir).unwrap();

        let result = lifecycle.create("test-id", &bundle_dir, None, &[]);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("config.json not found")
        );
    }

    #[test]
    fn test_create_already_exists() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        // Pre-create a container state
        let state = ContainerState::new("test-id".to_string(), bundle.clone());
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.create("test-id", &bundle, None, &[]);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_start_not_found() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let result = lifecycle.start("nonexistent");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_start_wrong_status_running() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        // Create a container in Running status (can't start again)
        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Running;
        state.pid = Some(12345);
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.start("test-id");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot start"));
        assert!(err.contains("running"));
    }

    #[test]
    fn test_start_wrong_status_stopped() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        // Create a container in Stopped status
        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Stopped;
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.start("test-id");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot start"));
        assert!(err.contains("stopped"));
    }

    #[test]
    fn test_state_not_found() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let result = lifecycle.state("nonexistent");

        assert!(result.is_err());
    }

    #[test]
    fn test_state_returns_container_state() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Created;
        state.pid = Some(999);
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.state("test-id").unwrap();

        assert_eq!(result.id, "test-id");
        assert_eq!(result.status, Status::Created);
        assert_eq!(result.pid, Some(999));
    }

    #[test]
    fn test_kill_not_found() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let result = lifecycle.kill("nonexistent", libc::SIGTERM);

        assert!(result.is_err());
    }

    #[test]
    fn test_kill_already_stopped() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Stopped;
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.kill("test-id", libc::SIGTERM);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already stopped"));
    }

    #[test]
    fn test_kill_no_pid() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Running;
        state.pid = None; // No PID
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.kill("test-id", libc::SIGTERM);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no PID"));
    }

    #[test]
    fn test_delete_not_found() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let result = lifecycle.delete("nonexistent", false);

        assert!(result.is_err());
    }

    #[test]
    fn test_delete_stopped_container() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Stopped;
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.delete("test-id", false);

        assert!(result.is_ok());
        assert!(!lifecycle.state_manager.exists("test-id"));
    }

    #[test]
    fn test_delete_running_without_force_fails() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        let mut state = ContainerState::new("test-id".to_string(), bundle);
        state.status = Status::Running;
        state.pid = Some(std::process::id()); // Use current process so it appears alive
        lifecycle.state_manager.save(&state).unwrap();

        let result = lifecycle.delete("test-id", false);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot delete"));
        assert!(err.contains("--force"));
    }

    #[test]
    fn test_list_empty() {
        let (_temp, lifecycle) = create_temp_lifecycle();

        let states = lifecycle.list().unwrap();

        assert!(states.is_empty());
    }

    #[test]
    fn test_list_multiple_containers() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        // Create multiple containers
        for i in 1..=3 {
            let mut state = ContainerState::new(format!("container-{i}"), bundle.clone());
            state.status = Status::Stopped;
            lifecycle.state_manager.save(&state).unwrap();
        }

        let mut states = lifecycle.list().unwrap();
        states.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(states.len(), 3);
        assert_eq!(states[0].id, "container-1");
        assert_eq!(states[1].id, "container-2");
        assert_eq!(states[2].id, "container-3");
    }

    #[test]
    fn test_list_skips_corrupted_state() {
        let (temp, lifecycle) = create_temp_lifecycle();
        let bundle = create_valid_bundle(&temp);

        // Create a valid container
        let state = ContainerState::new("valid-container".to_string(), bundle);
        lifecycle.state_manager.save(&state).unwrap();

        // Create a corrupted container (directory exists but state.json is invalid)
        let corrupted_dir = temp.path().join("containers").join("corrupted-container");
        fs::create_dir_all(&corrupted_dir).unwrap();
        fs::write(corrupted_dir.join("state.json"), "not valid json").unwrap();

        let states = lifecycle.list().unwrap();

        // Should only return the valid container
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].id, "valid-container");
    }

    #[test]
    fn test_run_hooks_success() {
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/bin/true")
            .build()
            .unwrap();
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_hooks_failure() {
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/bin/false")
            .build()
            .unwrap();
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed"));
    }

    #[test]
    fn test_run_hooks_nonexistent_binary() {
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/nonexistent/hook")
            .build()
            .unwrap();
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_run_hooks_with_args_and_env() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("hook_ran");
        // Use /bin/sh to create a marker file, proving args and env work
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("touch {}", marker.display()),
            ])
            .env(vec!["HOOK_TEST=1".to_string()])
            .build()
            .unwrap();
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_ok());
        assert!(marker.exists(), "hook should have created marker file");
    }

    #[test]
    fn test_run_hooks_timeout() {
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/bin/sleep")
            .args(vec!["sleep".to_string(), "60".to_string()])
            .timeout(1_i64)
            .build()
            .unwrap();
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn test_run_hooks_receives_state_on_stdin() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("stdin_capture");
        // Hook reads stdin and writes it to a file
        let hook = oci_spec::runtime::HookBuilder::default()
            .path("/bin/sh")
            .args(vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("cat > {}", output.display()),
            ])
            .build()
            .unwrap();
        let state = ContainerState::new("test-stdin".to_string(), PathBuf::from("/tmp/bundle"));
        let result = run_hooks(&[hook], &state, "test");
        assert!(result.is_ok());
        let captured = fs::read_to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(parsed["id"], "test-stdin");
        assert_eq!(parsed["bundle"], "/tmp/bundle");
    }

    #[test]
    fn test_run_hooks_sequential_stops_on_failure() {
        let temp = TempDir::new().unwrap();
        let marker = temp.path().join("should_not_exist");
        let hooks = vec![
            // First hook fails
            oci_spec::runtime::HookBuilder::default()
                .path("/bin/false")
                .build()
                .unwrap(),
            // Second hook should NOT run
            oci_spec::runtime::HookBuilder::default()
                .path("/bin/sh")
                .args(vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("touch {}", marker.display()),
                ])
                .build()
                .unwrap(),
        ];
        let state = ContainerState::new("test-seq".to_string(), PathBuf::from("/tmp"));
        let result = run_hooks(&hooks, &state, "test");
        assert!(result.is_err());
        assert!(
            !marker.exists(),
            "second hook should not run after first fails"
        );
    }

    #[test]
    fn test_run_hooks_empty_list() {
        let state = ContainerState::new("test-hook".to_string(), PathBuf::from("/tmp"));
        let result = run_hooks(&[], &state, "test");
        assert!(result.is_ok());
    }
}
