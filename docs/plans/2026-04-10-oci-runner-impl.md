# OCI Runner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Port the OCI-compliant container runtime to this repo, wiring it to the existing
forker + seccomp + 9P broker infrastructure.

**Architecture:** Thin OCI CLI adapter that spawns a `litebox_broker` for rootfs/networking,
constructs `CliArgs`, and delegates to `litebox_runner_linux_userland::run()`. Full OCI
lifecycle (create/start/state/kill/delete) ported from old runner. All fork workarounds removed.

**Tech Stack:** Rust, clap 4.5, oci-spec 0.8, serde/serde_json, nix 0.29, libc 0.2

---

### Task 1: Create crate skeleton and add to workspace

**Files:**
- Create: `litebox_runner_oci/Cargo.toml`
- Create: `litebox_runner_oci/src/lib.rs`
- Create: `litebox_runner_oci/src/main.rs`
- Modify: `Cargo.toml` (workspace root)

**Step 1: Create Cargo.toml**

```toml
[package]
name = "litebox_runner_oci"
version = "0.1.0"
edition = "2024"
description = "OCI-compliant container runtime using LiteBox sandbox"

[dependencies]
# OCI spec parsing
oci-spec = { version = "0.8", features = ["runtime"] }

# CLI
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"

# LiteBox core
litebox_runner_linux_userland = { path = "../litebox_runner_linux_userland" }

# Utilities
libc = "0.2"
nix = { version = "0.29", features = ["signal", "process"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
tempfile = "3"

[lints]
workspace = true
```

**Step 2: Create minimal lib.rs**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI-compliant container runtime using LiteBox sandbox.

pub mod lifecycle;
mod runner;
pub mod state;

pub use runner::run_container;
pub use runner::NetworkConfig;
pub use runner::CniNetworkConfig;
```

**Step 3: Create minimal main.rs**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI-compliant container runtime CLI.

fn main() -> anyhow::Result<()> {
    Ok(())
}
```

**Step 4: Add to workspace Cargo.toml**

Add `"litebox_runner_oci"` to both `members` and `default-members` arrays.

**Step 5: Create empty module files**

Create `litebox_runner_oci/src/state.rs`, `litebox_runner_oci/src/lifecycle.rs`,
and `litebox_runner_oci/src/runner.rs` as empty files with module doc comments.

**Step 6: Verify it compiles**

Run: `cargo check -p litebox_runner_oci`
Expected: Success

**Step 7: Commit**

```
feat: add litebox_runner_oci crate skeleton
```

---

### Task 2: Port state.rs (state management)

**Files:**
- Write: `litebox_runner_oci/src/state.rs`

**Context:** Port from `https://raw.githubusercontent.com/sangho2/litebox/oci/litebox_runner_oci/src/state.rs`.
This file is self-contained — it depends only on serde, serde_json, anyhow, and std.
Port it **verbatim** (all types, all methods, all tests). No changes needed.

**Key types:**
- `Status` — Creating/Created/Running/Stopped enum
- `ContainerState` — OCI state with ociVersion, id, status, pid, bundle, annotations, exit_code
- `StateManager` — disk persistence (save/load/update/delete/list/refresh_state)

**Step 1: Write state.rs**

Copy the complete source from the old runner. The code is self-contained and requires
no adaptation for the new codebase.

**Step 2: Verify compilation**

Run: `cargo check -p litebox_runner_oci`

**Step 3: Run unit tests**

Run: `cargo test -p litebox_runner_oci -- state`
Expected: All 18 state tests pass

**Step 4: Commit**

```
feat(oci): add state management module
```

---

### Task 3: Port lifecycle.rs (OCI lifecycle)

**Files:**
- Write: `litebox_runner_oci/src/lifecycle.rs`

**Context:** Port from the old runner. This file depends on state.rs (already ported),
oci-spec (for hooks), nix (for fork/kill), and std Unix facilities.

**Key components:**
- `setup_console_socket()` — PTY creation + SCM_RIGHTS to console-socket
- `should_unshare_netns()` — check OCI spec for network namespace
- `run_hooks()` — execute OCI lifecycle hooks with state JSON on stdin
- `Lifecycle` struct — create/start/state/kill/delete/list methods

Port **verbatim**. The only change: the `create` method's child process execs into
`litebox-oci run` — this is identical to the old behavior.

**Step 1: Write lifecycle.rs**

Copy the complete source from the old runner. No adaptations needed.

**Step 2: Verify compilation**

Run: `cargo check -p litebox_runner_oci`

**Step 3: Run unit tests**

Run: `cargo test -p litebox_runner_oci -- lifecycle`
Expected: All 18 lifecycle tests pass (note: `test_run_hooks_timeout` takes ~1s)

**Step 4: Commit**

```
feat(oci): add OCI lifecycle management
```

---

### Task 4: Write runner.rs (the new core)

**Files:**
- Write: `litebox_runner_oci/src/runner.rs`

**Context:** This is the NEW module — not ported from old runner. It replaces the old
runner's 1400+ lines of rootfs walking, rewriting, and platform init with ~200 lines
that spawn a broker and delegate to `litebox_runner_linux_userland::run()`.

**Key functions:**
- `run_container()` — public entry point
- `detect_cni_network()` — auto-detect CNI from OCI spec (ported from old runner)
- `setup_cni_tun()` — create TUN inside CNI netns (ported from old runner)
- `spawn_broker()` — spawn litebox_broker child process
- `build_cli_args()` — construct CliArgs from OCI spec

**Step 1: Write runner.rs**

The module structure:

```rust
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use anyhow::{Context, Result};
use oci_spec::runtime::Spec;

/// Network configuration for container.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    pub tun_device: Option<String>,
    pub cni: Option<CniNetworkConfig>,
}

/// CNI-detected network configuration.
#[derive(Debug, Clone)]
pub struct CniNetworkConfig {
    pub netns_path: Option<PathBuf>,
    pub ip_addr: std::net::Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: std::net::Ipv4Addr,
    pub mtu: u16,
}

/// Detect CNI network configuration from OCI spec.
pub fn detect_cni_network(spec: &Spec) -> Option<CniNetworkConfig> {
    // Port from old runner: read netns, enter it, read interface config
}

/// Set up TUN device inside CNI netns.
fn setup_cni_tun(cni: &CniNetworkConfig) -> Result<String> {
    // Port from old runner: create TUN, configure IP, enable forwarding, NAT
}

/// Spawn a litebox_broker process serving the rootfs.
/// Returns (child process, socket path).
fn spawn_broker(rootfs: &Path, socket_path: &str, rewrite_syscalls: bool) -> Result<Child> {
    // Find litebox_broker binary (same dir as current exe, or PATH)
    let broker_exe = find_broker_exe()?;
    let child = Command::new(&broker_exe)
        .arg("--network-proxy-listen").arg(socket_path)
        .arg("--root-dir").arg(rootfs)
        .arg("--rewrite-syscalls")  // if rewrite_syscalls
        .arg("--read-only")
        .arg("--writable-path").arg("/tmp")
        .arg("--writable-path").arg("/var")
        .spawn()
        .context("failed to spawn litebox_broker")?;
    // Wait briefly for socket to appear
    Ok(child)
}

/// Find the litebox_broker executable.
fn find_broker_exe() -> Result<PathBuf> {
    // Check same directory as current executable
    let self_exe = std::env::current_exe()?;
    let broker = self_exe.parent().unwrap().join("litebox_broker");
    if broker.exists() { return Ok(broker); }
    // Try cargo target dir
    // Fallback to PATH
    which::which("litebox_broker")
        .or_else(|_| anyhow::bail!("litebox_broker not found"))
}

/// Build CliArgs from OCI spec for the existing runner.
fn build_cli_args(
    spec: &Spec,
    extra_env: &[String],
    broker_socket: &str,
    tun_device: Option<&str>,
) -> Result<litebox_runner_linux_userland::CliArgs> {
    let process = spec.process().as_ref()
        .context("OCI spec missing 'process'")?;
    let args = process.args().as_ref()
        .context("OCI spec missing 'process.args'")?;

    // Build environment variables
    let mut env_vars: Vec<String> = Vec::new();
    if let Some(env) = process.env() {
        env_vars.extend(env.iter().cloned());
    }
    env_vars.extend(extra_env.iter().cloned());

    // Get working directory
    let cwd = process.cwd().as_ref()
        .map(|p| p.to_string_lossy().to_string());

    Ok(litebox_runner_linux_userland::CliArgs {
        program_and_arguments: args.clone(),
        environment_variables: env_vars,
        forward_environment_variables: false,
        unstable: true,
        insert_files: Vec::new(),
        initial_files: None,
        rewrite_syscalls: false,  // broker handles this
        interception_backend: litebox_runner_linux_userland::InterceptionBackend::Seccomp,
        tun_device_name: tun_device.map(String::from),
        network_broker: Some(broker_socket.to_string()),
        program_from_tar: false,
        nine_p_broker: Some(broker_socket.to_string()),
        working_directory: cwd,
        // Internal flags — all None/false/empty
        worker_exec: false,
        worker_exec_fd: None,
        worker_result_fd: None,
        worker_interp_fd: None,
        worker_interp_path: None,
        guest_pid: None,
        guest_ppid: None,
        guest_uid: None,
        guest_euid: None,
        guest_gid: None,
        guest_egid: None,
        fork_restore: false,
        fork_restore_fd: None,
        fork_restore_ack_fd: None,
        pipe_bridge: Vec::new(),
        mux_fd: None,
        mux_stream: Vec::new(),
        local_pipe: Vec::new(),
    })
}

/// Run an OCI container.
pub fn run_container(
    bundle_path: &Path,
    override_args: Option<&[String]>,
    extra_env: &[String],
    network: &NetworkConfig,
) -> Result<i32> {
    let spec_path = bundle_path.join("config.json");
    let spec: Spec = serde_json::from_reader(
        std::fs::File::open(&spec_path)?
    )?;

    let rootfs_path = bundle_path.join(
        spec.root().as_ref().map_or(
            std::path::Path::new("rootfs"),
            |r| r.path().as_path()
        )
    );

    // Detect CNI network
    let effective_network = if network.tun_device.is_some() {
        network.clone()
    } else {
        match detect_cni_network(&spec) {
            Some(cni) => match setup_cni_tun(&cni) {
                Ok(tun) => NetworkConfig { tun_device: Some(tun), cni: Some(cni) },
                Err(_) => network.clone(),
            },
            None => network.clone(),
        }
    };

    // Generate broker socket path
    let broker_socket = format!("/tmp/litebox-oci-{}.sock", std::process::id());

    // Spawn broker
    let mut broker = spawn_broker(
        &rootfs_path,
        &broker_socket,
        true,  // rewrite_syscalls
    )?;

    // Wait for broker socket to appear (up to 5 seconds)
    wait_for_socket(&broker_socket, std::time::Duration::from_secs(5))?;

    // Build CliArgs
    let cli_args = build_cli_args(
        &spec,
        extra_env,
        &broker_socket,
        effective_network.tun_device.as_deref(),
    )?;

    // Run — this diverges (calls exit internally)
    let result = litebox_runner_linux_userland::run(cli_args);

    // Clean up broker
    let _ = broker.kill();
    let _ = std::fs::remove_file(&broker_socket);

    result.map(|()| 0)
}
```

**Step 2: Add `which` dependency to Cargo.toml** (for finding broker binary)

Actually, skip `which` — just check same-dir and `PATH` manually.

**Step 3: Verify compilation**

Run: `cargo check -p litebox_runner_oci`

**Step 4: Commit**

```
feat(oci): add runner module with broker spawning and CliArgs construction
```

---

### Task 5: Write main.rs (CLI)

**Files:**
- Write: `litebox_runner_oci/src/main.rs`

**Context:** Port the CLI from the old runner. Strip all fork-workaround flags
(`--no-rewrite-shell`, `--lazy`, `--lazy-tar`, `--lazy-rewrite`). Keep all OCI lifecycle
commands, containerd/podman compatibility flags, and networking flags.

The `run` and `exec` commands call `runner::run_container()`.
The `create/start/state/kill/delete/list/events` commands use `lifecycle::Lifecycle`.

**Step 1: Write main.rs**

Port from old runner with these changes:
- Remove: `--lazy`, `--lazy-tar`, `--lazy-rewrite`, `--no-rewrite-shell` flags
- Remove: `LazyMode` enum usage
- Remove: `parse_mounts()` (bind mounts handled differently now — via broker writable paths)
- Remove: `mount` field from Run/Exec commands (for now)
- Remove: `StdioRedirect` usage (stdio works natively now)
- Keep: All OCI lifecycle commands
- Keep: `--tun-device` flag (global + per-command)
- Keep: `--env`, `--env-file` flags
- Keep: `--stdout`, `--stderr` (for logging redirection)
- Keep: `--console-socket` in create
- Keep: `--systemd-cgroup` (accepted, ignored)
- Keep: `events --stats`
- Remove: `build.rs` (was only for litebox-sh)
- Remove: version_string() using GIT_HASH/GIT_DIRTY (simplify)

**Step 2: Update lib.rs exports**

```rust
pub mod lifecycle;
mod runner;
pub mod state;

pub use runner::run_container;
pub use runner::NetworkConfig;
pub use runner::CniNetworkConfig;
```

**Step 3: Verify compilation**

Run: `cargo check -p litebox_runner_oci`

**Step 4: Commit**

```
feat(oci): add OCI CLI with full lifecycle commands
```

---

### Task 6: Integration test — echo hello

**Files:**
- Create: `litebox_runner_oci/tests/integration.rs` (or test via shell script)

**Step 1: Build**

Run: `cargo build -p litebox_runner_oci -p litebox_broker --release`

**Step 2: Create test bundle**

```bash
mkdir -p /tmp/test-bundle/rootfs
# Copy a minimal rootfs (e.g., busybox static binary)
cp /bin/echo /tmp/test-bundle/rootfs/bin/echo  # or use alpine rootfs
cat > /tmp/test-bundle/config.json << 'EOF'
{
    "ociVersion": "1.0.0",
    "root": { "path": "rootfs" },
    "process": {
        "args": ["/bin/echo", "Hello from LiteBox OCI with fork!"],
        "env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
        "cwd": "/"
    }
}
EOF
```

**Step 3: Run**

Run: `./target/release/litebox_runner_oci run --bundle /tmp/test-bundle test-container`
Expected: Prints "Hello from LiteBox OCI with fork!" and exits 0

**Step 4: Test fork actually works**

Create a bundle with a shell script that uses fork:
```bash
echo '#!/bin/sh
echo "parent: $$"
ls / | head -5
echo "done"' > /tmp/test-bundle/rootfs/test.sh
chmod +x /tmp/test-bundle/rootfs/test.sh
```

Update config.json to run `/bin/sh /test.sh`. This should work because real `sh` can
fork+exec now.

**Step 5: Commit**

```
test(oci): add basic integration test
```

---

### Task 7: Polish and verify

**Step 1: Run all unit tests**

Run: `cargo test -p litebox_runner_oci`
Expected: All 36+ unit tests pass (18 state + 18 lifecycle)

**Step 2: Run clippy**

Run: `cargo clippy -p litebox_runner_oci`
Expected: No warnings

**Step 3: Test OCI lifecycle (create/start)**

```bash
litebox_runner_oci create --bundle /tmp/test-bundle --pid-file /tmp/test.pid test-lifecycle
litebox_runner_oci state test-lifecycle  # should show "created"
litebox_runner_oci start test-lifecycle  # should run and eventually stop
litebox_runner_oci state test-lifecycle  # should show "stopped"
litebox_runner_oci delete test-lifecycle
```

**Step 4: Commit**

```
feat(oci): OCI runner with fork support — initial release
```
