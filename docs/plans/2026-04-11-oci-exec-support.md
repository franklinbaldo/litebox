# OCI Exec Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `podman exec` work by implementing the OCI exec protocol that conmon expects — parsing process.json, forking with PTY setup, writing PID files, and running a new litebox sandbox with the same rootfs.

**Architecture:** Conmon invokes `litebox-oci exec --process <process.json> --pid-file <path> [--console-socket <path>] [--tty] --detach <container-id>`. The handler reads process.json for args/env/cwd/user, loads the container state for the bundle path, forks (parent exits immediately for `--detach`), optionally sets up PTY via the existing `setup_console_socket()`, writes the child PID to `--pid-file`, and calls `run_container()` with overrides from process.json.

**Tech Stack:** Rust, clap (CLI parsing), oci-spec crate, serde_json, Unix fork/PTY/SCM_RIGHTS.

---

### Task 1: Update Exec CLI to Accept Podman Flags

**Files:**
- Modify: `litebox_runner_oci/src/main.rs:159-183` (Exec variant)

**Context:**
Podman (via conmon) invokes exec as:
```
litebox-oci exec --pid-file <path> --process <process.json> --detach [--tty] [--console-socket <path>] <container-id>
```
The current Exec variant only accepts `container_id`, `env`, `env_file`, `tun_device`, `command`. We need to add the missing flags and make `command` optional (since args come from `--process`).

**Step 1: Update the Exec clap definition**

Replace the entire `Exec` variant (lines 159-183) with:

```rust
    /// Execute a command in a container's rootfs.
    ///
    /// When invoked with --process, reads args/env/cwd/user from the process
    /// spec JSON file (as conmon/Podman does). Otherwise falls back to the
    /// positional command args.
    ///
    /// With --detach, forks and the parent exits immediately (for conmon).
    Exec {
        /// Container ID
        container_id: String,

        /// Path to OCI process spec JSON file (as passed by conmon).
        /// When provided, args/env/cwd/user are read from this file.
        #[clap(short, long, value_name = "FILE")]
        process: Option<PathBuf>,

        /// Console socket path for PTY support (exec with --tty).
        #[clap(long)]
        console_socket: Option<PathBuf>,

        /// File to write the exec process PID to.
        #[clap(long)]
        pid_file: Option<PathBuf>,

        /// Run exec'd process in background (parent exits immediately).
        #[clap(long)]
        detach: bool,

        /// Allocate a pseudo-TTY (accepted for Podman compat, actual TTY
        /// setup is driven by --console-socket).
        #[clap(long)]
        tty: bool,

        /// Set environment variables (can be specified multiple times)
        #[clap(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Read environment variables from a file (one KEY=VALUE per line)
        #[clap(long, value_name = "FILE")]
        env_file: Option<PathBuf>,

        /// TUN device name for container networking (e.g., "tun99").
        #[clap(long, value_name = "DEVICE")]
        tun_device: Option<String>,

        /// Command and arguments to execute (used when --process is not given)
        #[clap(num_args = 0..)]
        command: Vec<String>,
    },
```

Key changes:
- `--process` / `-p` for process.json path
- `--console-socket` for PTY
- `--pid-file` for conmon PID tracking
- `--detach` flag
- `--tty` flag (accepted, actual behavior driven by `--console-socket`)
- `command` is now `num_args = 0..` (no longer required; args come from `--process`)

**Step 2: Build and verify CLI parses**

Run: `cargo build -p litebox_runner_oci 2>&1`
Expected: Build succeeds (handler will have compile errors from new fields, that's OK — we fix in Task 2).

Actually — the handler destructures the enum, so update it minimally to compile.

**Step 3: Update exec handler to destructure new fields**

In `main.rs` (around line 505), replace the exec handler's destructure pattern to include all new fields. For now, keep the old behavior as fallback:

```rust
        Command::Exec {
            container_id,
            process,
            console_socket,
            pid_file,
            detach,
            tty: _,
            env,
            env_file,
            tun_device,
            command,
        } => {
            tracing::info!(
                container_id = %container_id,
                process = ?process,
                detach,
                "exec in container"
            );

            // Load container state to get bundle path
            let state = lifecycle.state(&container_id)?;
            let bundle = state.bundle;

            // Set up network configuration
            let network = litebox_runner_oci::NetworkConfig {
                tun_device: tun_device.clone(),
                cni: None,
            };

            let extra_env = parse_extra_env(&env, env_file.as_ref())?;

            // If --process is provided, parse process.json for args/env/cwd/user
            let (override_command, process_env, process_cwd, process_user) =
                if let Some(ref process_path) = process {
                    litebox_runner_oci::parse_process_spec(process_path)?
                } else {
                    (command.clone(), vec![], None, None)
                };

            // Merge process env with CLI env (CLI env takes precedence)
            let mut merged_env = process_env;
            merged_env.extend(extra_env);

            let override_args = if override_command.is_empty() {
                None
            } else {
                Some(override_command.as_slice())
            };

            // Exec with fork+detach+PTY support
            let exit_code = litebox_runner_oci::exec_container(
                &bundle,
                override_args,
                &merged_env,
                &network,
                console_socket.as_deref(),
                pid_file.as_deref(),
                detach,
                process_cwd.as_deref(),
                process_user.as_ref(),
            )?;
            std::process::exit(exit_code);
        }
```

**Step 4: Build (expect compile error for missing functions)**

Run: `cargo build -p litebox_runner_oci 2>&1`
Expected: Compile error — `parse_process_spec` and `exec_container` don't exist yet. That's correct; we add them in Tasks 2 and 3.

**Step 5: Add stubs to lib.rs to make it compile**

In `litebox_runner_oci/src/runner.rs`, add stub functions:

```rust
/// Parse an OCI process spec JSON file (as created by Podman for exec).
///
/// Returns (args, env, cwd, user) extracted from the process spec.
pub fn parse_process_spec(
    path: &Path,
) -> Result<(Vec<String>, Vec<String>, Option<String>, Option<(u32, u32)>)> {
    anyhow::bail!("parse_process_spec not yet implemented")
}

/// Execute a command in a container with fork/detach/PTY support.
///
/// This is the exec entry point used by `podman exec` (via conmon).
pub fn exec_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
    console_socket: Option<&Path>,
    pid_file: Option<&Path>,
    detach: bool,
    working_directory: Option<&str>,
    user: Option<&(u32, u32)>,
) -> Result<i32> {
    anyhow::bail!("exec_container not yet implemented")
}
```

In `litebox_runner_oci/src/lib.rs`, add exports:

```rust
pub use runner::exec_container;
pub use runner::parse_process_spec;
```

**Step 6: Build and verify it compiles**

Run: `cargo build -p litebox_runner_oci 2>&1`
Expected: Clean build.

**Step 7: Commit**

```
feat(oci): add exec CLI flags for Podman compatibility

Accept --process, --pid-file, --console-socket, --detach, and --tty
flags on the exec subcommand matching what conmon passes. Stub out
parse_process_spec() and exec_container() for implementation in
subsequent tasks.
```

---

### Task 2: Implement process.json Parsing

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs` (replace `parse_process_spec` stub)

**Context:**
The process.json file created by Podman looks like:
```json
{
    "user": {"uid": 0, "gid": 0, "umask": 18},
    "args": ["echo", "hello"],
    "env": ["PATH=/usr/local/sbin:...", "HOME=/root"],
    "cwd": "/",
    "capabilities": { ... }
}
```
We use `oci_spec::runtime::Process` to deserialize it.

**Step 1: Write tests**

Add to the `#[cfg(test)] mod tests` block in `runner.rs`:

```rust
    #[test]
    fn parse_process_spec_extracts_args_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("process.json");
        std::fs::write(
            &path,
            r#"{
                "args": ["echo", "hello"],
                "env": ["PATH=/bin", "HOME=/root"],
                "cwd": "/tmp",
                "user": {"uid": 1000, "gid": 1000}
            }"#,
        )
        .unwrap();

        let (args, env, cwd, user) = super::parse_process_spec(&path).unwrap();
        assert_eq!(args, vec!["echo", "hello"]);
        assert_eq!(env, vec!["PATH=/bin", "HOME=/root"]);
        assert_eq!(cwd, Some("/tmp".to_string()));
        assert_eq!(user, Some((1000, 1000)));
    }

    #[test]
    fn parse_process_spec_handles_minimal_spec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("process.json");
        std::fs::write(
            &path,
            r#"{"args": ["sh"]}"#,
        )
        .unwrap();

        let (args, env, cwd, user) = super::parse_process_spec(&path).unwrap();
        assert_eq!(args, vec!["sh"]);
        assert!(env.is_empty());
        assert!(cwd.is_none() || cwd == Some(String::new()));
        // user may be None or Some((0,0)) depending on OCI defaults
    }

    #[test]
    fn parse_process_spec_fails_on_missing_file() {
        let result = super::parse_process_spec(Path::new("/nonexistent/process.json"));
        assert!(result.is_err());
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p litebox_runner_oci --lib -- parse_process_spec 2>&1`
Expected: All 3 tests fail (stub returns bail!).

**Step 3: Implement parse_process_spec**

Replace the stub in `runner.rs`:

```rust
/// Parse an OCI process spec JSON file (as created by Podman for exec).
///
/// Returns (args, env, cwd, user) extracted from the process spec.
/// The process.json follows the OCI runtime spec `process` schema.
pub fn parse_process_spec(
    path: &Path,
) -> Result<(Vec<String>, Vec<String>, Option<String>, Option<(u32, u32)>)> {
    use oci_spec::runtime::Process;

    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open process spec: {}", path.display()))?;
    let process: Process = serde_json::from_reader(file)
        .with_context(|| format!("failed to parse process spec: {}", path.display()))?;

    let args = process
        .args()
        .as_ref()
        .cloned()
        .unwrap_or_default();

    let env = process
        .env()
        .as_ref()
        .cloned()
        .unwrap_or_default();

    let cwd = {
        let cwd_str = process.cwd().to_string_lossy().to_string();
        if cwd_str.is_empty() {
            None
        } else {
            Some(cwd_str)
        }
    };

    let user = process.user().uid().as_raw().checked_add(0).map(|uid| {
        (uid, process.user().gid().as_raw())
    });

    Ok((args, env, cwd, user))
}
```

Note: The `oci_spec` crate's `Process::user()` returns a `User` with `.uid()` and `.gid()`. Check the exact API — it may return `Uid`/`Gid` wrappers. Adjust accordingly. The oci_spec `User` `.uid()` returns `u32` directly in most versions. If it returns `nix::Uid`, call `.as_raw()`.

The implementation should handle these fields from the process.json:
- `args` → command + arguments
- `env` → environment variables
- `cwd` → working directory
- `user.uid` / `user.gid` → UID/GID pair

Fields we intentionally ignore: `capabilities`, `noNewPrivileges`, `apparmorProfile`, `selinuxLabel`, `rlimits`, `umask`.

**Step 4: Run tests to verify they pass**

Run: `cargo test -p litebox_runner_oci --lib -- parse_process_spec 2>&1`
Expected: All 3 pass.

**Step 5: Commit**

```
feat(oci): implement process.json parsing for exec

Parse the OCI process spec file that Podman creates for exec sessions,
extracting args, env, cwd, and user fields.
```

---

### Task 3: Implement exec_container with Fork/Detach/PTY

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs` (replace `exec_container` stub)
- Modify: `litebox_runner_oci/src/lifecycle.rs` (make `setup_console_socket` pub(crate))

**Context:**
The exec_container function must:
1. If `--detach`: fork. Parent writes child PID to `--pid-file` and returns 0. Child continues.
2. If `--console-socket`: set up PTY (reuse `setup_console_socket` from lifecycle.rs).
3. Call `run_container()` with the appropriate overrides.

The fork+detach pattern mirrors what `lifecycle::create()` does, but simpler — no sync socket needed since exec runs immediately.

**Step 1: Make setup_console_socket accessible**

In `litebox_runner_oci/src/lifecycle.rs`, change line 24 from:
```rust
fn setup_console_socket(console_socket_path: &Path) -> Result<std::os::fd::OwnedFd> {
```
to:
```rust
pub(crate) fn setup_console_socket(console_socket_path: &Path) -> Result<std::os::fd::OwnedFd> {
```

**Step 2: Implement exec_container**

Replace the stub in `runner.rs`. The function needs to handle:

A. **`run_container` needs to accept optional cwd and user overrides.** Currently `build_cli_args` reads cwd and user from the OCI spec. For exec, these may differ from the original spec (process.json has its own user/cwd). The simplest approach: extend `run_container` to accept optional overrides, OR build CliArgs in `exec_container` directly.

The cleanest approach: `exec_container` calls `run_container` after temporarily overriding the relevant parts. But `run_container` reads config.json internally. Instead, let's add optional cwd/user override params to `run_container`.

Actually, the simplest: `exec_container` handles its own fork/PTY/pid-file logic, then calls the existing `run_container()`. The `override_args` already lets us pass different args, and `extra_env` handles env. For cwd and user, we can pass them via `extra_env` as special env vars, or we need to modify `run_container`/`build_cli_args`.

Best approach: Add optional `override_cwd: Option<&str>` and `override_user: Option<(u32, u32)>` params to `run_container`. This is a clean API change.

```rust
/// Execute a command in a container with fork/detach/PTY support.
///
/// This is the exec entry point used by `podman exec` (via conmon).
/// When `detach` is true, forks and the parent exits with 0 after writing
/// the child PID to `pid_file`. The child runs the sandbox.
pub fn exec_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
    console_socket: Option<&Path>,
    pid_file: Option<&Path>,
    detach: bool,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
) -> Result<i32> {
    if detach {
        // Fork: parent writes PID and returns, child runs the sandbox.
        match unsafe { libc::fork() } {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child — fall through to run sandbox below.
                // Create new session so the child isn't killed when parent exits.
                unsafe { libc::setsid(); }
            }
            child_pid => {
                // Parent — write PID file and exit.
                if let Some(pf) = pid_file {
                    std::fs::write(pf, format!("{child_pid}\n"))
                        .with_context(|| format!("failed to write pid-file: {}", pf.display()))?;
                }
                return Ok(0);
            }
        }
    } else if let Some(pf) = pid_file {
        // Non-detach: write our own PID.
        let pid = std::process::id();
        std::fs::write(pf, format!("{pid}\n"))
            .with_context(|| format!("failed to write pid-file: {}", pf.display()))?;
    }

    // Set up PTY if console-socket was provided.
    if let Some(cs_path) = console_socket {
        use std::os::fd::AsRawFd;
        let slave_fd = crate::lifecycle::setup_console_socket(cs_path)?;
        let raw = slave_fd.as_raw_fd();
        unsafe {
            libc::setsid();
            libc::dup2(raw, 0);
            libc::dup2(raw, 1);
            libc::dup2(raw, 2);
            libc::ioctl(raw, libc::TIOCSCTTY, 0);
        }
        drop(slave_fd);
    }

    // Run the sandbox — reuse run_container with overrides.
    run_container(
        bundle_path,
        override_args,
        extra_env,
        network,
        override_cwd,
        override_user,
    )
}
```

**Step 3: Add override_cwd and override_user params to run_container**

Update `run_container` signature:

```rust
pub fn run_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
) -> Result<i32> {
```

And add corresponding params to `build_cli_args`:

```rust
fn build_cli_args(
    spec: &Spec,
    ...,
    override_cwd: Option<&str>,
    override_user: Option<&(u32, u32)>,
) -> Result<CliArgs> {
```

In `build_cli_args`, use the overrides when present:
- For working_directory: `override_cwd.map(String::from).or_else(|| ... existing cwd logic ...)`
- For UID/GID: `if let Some(&(uid, gid)) = override_user { ... } else { ... existing user logic ... }`

**Step 4: Update existing call sites in main.rs**

The `Run` command handler calls `run_container(...)`. Update it to pass `None, None` for the new params:

```rust
let exit_code = litebox_runner_oci::run_container(
    &bundle, None, &extra_env, &network, None, None,
)?;
```

**Step 5: Build and verify**

Run: `cargo build -p litebox_runner_oci 2>&1`
Expected: Clean build.

**Step 6: Run all existing tests**

Run: `cargo test -p litebox_runner_oci --lib 2>&1`
Expected: All tests pass (including the parse_process_spec tests from Task 2).

**Step 7: Commit**

```
feat(oci): implement exec_container with fork/detach/PTY support

Fork on --detach (as conmon requires), set up PTY via console-socket,
write PID file, then run a new litebox sandbox with the same rootfs.
Supports both TTY and pipe-mode exec sessions.
```

---

### Task 4: Integration Test with Podman

**Files:**
- No code changes — testing only.

**Step 1: Install updated binary**

```bash
cargo build -p litebox_runner_oci --release 2>&1
sudo cp target/release/litebox-oci /usr/local/bin/litebox-oci
```

**Step 2: Test basic exec**

```bash
# Start a background container
podman run -d --name exec-test alpine sleep 300

# Non-TTY exec
podman exec exec-test echo hello
# Expected: "hello"

# Exec with environment variable
podman exec -e FOO=bar exec-test sh -c 'echo $FOO'
# Expected: "bar"

# Exec with working directory
podman exec -w /tmp exec-test pwd
# Expected: "/tmp"

# TTY exec
podman exec -t exec-test echo "tty test"
# Expected: "tty test"

# Cleanup
podman rm -f exec-test
```

**Step 3: Test exit codes**

```bash
podman run -d --name exec-test alpine sleep 300
podman exec exec-test sh -c 'exit 42'
echo "exit code: $?"
# Expected: "exit code: 42"
podman rm -f exec-test
```

**Step 4: Commit (if any fixes were needed)**

Commit any fixes discovered during integration testing.

---

### Task 5: Clippy + Fmt Cleanup

**Step 1:** Run `cargo fmt -p litebox_runner_oci`
**Step 2:** Run `cargo clippy -p litebox_runner_oci 2>&1 | grep runner.rs` — fix any new warnings.
**Step 3:** Run `cargo test -p litebox_runner_oci --lib` — verify all tests pass.
**Step 4:** Commit cleanup if needed.
