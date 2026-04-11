# Worker-Exec via Forker Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate `posix_spawn("/proc/self/exe", "--worker-exec", ...)` from the non-PIE
execve path by routing worker-exec through the existing forker process, just like
fork-restore already does.

**Architecture:** Extend `ForkRequest` with a `kind` field (`ForkRestore` vs `WorkerExec`).
For worker-exec, serialize exec metadata (args, env, cwd, guest identity, infrastructure
flags) into a memfd and pass exec image(s) as additional SCM_RIGHTS fds. The forker's
grandchild calls the existing `WORKER_CALLBACK`, which dispatches to either fork-restore
or worker-exec logic based on `kind`. The parent-side bridge thread wiring is shared.

**Tech Stack:** Rust, libc, Unix socketpair + SCM_RIGHTS, memfd_create

**Why this works:** The forker process has a minimal VA footprint. When it `fork()`s, the
grandchild inherits the forker's tiny address space — plenty of room for non-PIE binaries
at 0x400000. No `execve` needed; the shim loader maps the binary in-process.

---

### Task 1: Extend ForkRequest with `kind` and exec-specific fd indices

**Files:**
- Modify: `litebox_platform_linux_userland/src/forker.rs`

**Step 1: Add `ForkRequestKind` enum and new fields to `ForkRequest`**

Add after `StdioBinding`:

```rust
/// The kind of work the forked worker should perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRequestKind {
    /// Restore from a ForkSnapshot memfd (existing fork-restore path).
    ForkRestore = 0,
    /// Boot a new shim and load a non-PIE binary from exec image memfd(s).
    WorkerExec = 1,
}
```

Add to `ForkRequest`:

```rust
pub struct ForkRequest {
    /// What kind of work the worker should do.
    pub kind: ForkRequestKind,
    // ... existing fields ...
    /// Index into the SCM_RIGHTS array for the exec image memfd (0xFF = none).
    /// Only used when kind == WorkerExec.
    pub exec_image_fd_idx: u8,
    /// Index for the interpreter image memfd (0xFF = none).
    /// Only used when kind == WorkerExec.
    pub interp_image_fd_idx: u8,
}
```

**Step 2: Update serialize/deserialize**

Bump `FORK_REQUEST_VERSION` to 2. After the existing magic+version header, serialize
`kind` as a single u8 (0 = ForkRestore, 1 = WorkerExec). After the existing 4 fd-index
bytes (snapshot, ack, result, mux), serialize `exec_image_fd_idx` and
`interp_image_fd_idx` as 2 bytes.

In `serialize()`:
```rust
// After version
out.push(self.kind as u8);
// ... existing stdio, num_fds, fd indices ...
// After mux_fd_idx
out.push(self.exec_image_fd_idx);
out.push(self.interp_image_fd_idx);
```

In `deserialize()`:
```rust
// After version check
let kind_byte = data[pos];
pos += 1;
let kind = match kind_byte {
    0 => ForkRequestKind::ForkRestore,
    1 => ForkRequestKind::WorkerExec,
    _ => return Err("ForkRequest: unknown kind"),
};
// ... existing stdio, num_fds, fd indices ...
// After mux_fd_idx
let exec_image_fd_idx = data[pos];
let interp_image_fd_idx = data[pos + 1];
pos += 2;
```

**Step 3: Fix all existing ForkRequest construction sites**

Add `kind: ForkRequestKind::ForkRestore, exec_image_fd_idx: 0xFF, interp_image_fd_idx: 0xFF`
to the two places that build ForkRequests:
- `litebox_platform_linux_userland/src/lib.rs` in `try_spawn_via_forker` (~line 1063)
- All test ForkRequest literals in `forker.rs` tests

**Step 4: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All existing forker tests pass (with updated literals).

**Step 5: Add round-trip test for WorkerExec kind**

```rust
#[test]
fn fork_request_round_trip_worker_exec() {
    let req = ForkRequest {
        kind: ForkRequestKind::WorkerExec,
        stdio: [
            StdioBinding::Inherit,
            StdioBinding::Inherit,
            StdioBinding::Inherit,
        ],
        num_fds: 4,
        snapshot_fd_idx: 0,  // metadata memfd
        ack_fd_idx: 0xFF,
        result_fd_idx: 1,
        mux_fd_idx: 0xFF,
        exec_image_fd_idx: 2,
        interp_image_fd_idx: 3,
        mux_streams: vec![],
        pipe_bridges: vec![],
        local_pipes: vec![],
    };
    let data = req.serialize();
    let decoded = ForkRequest::deserialize(&data).expect("deserialize");
    assert_eq!(req, decoded);
}
```

**Step 6: Run all forker tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All tests pass including new one.

**Step 7: Commit**

```
feat(forker): extend ForkRequest with kind field and exec image fd indices
```

---

### Task 2: Add WorkerExecParams serialization

**Files:**
- Modify: `litebox_platform_linux_userland/src/forker.rs`

**Context:** `WorkerExecParams` encodes everything the worker child needs to run a
non-PIE binary — the data that was previously passed as CLI args to the posix_spawn'd
process. This struct is serialized into a memfd and passed via SCM_RIGHTS.

**Step 1: Define WorkerExecParams and serialize/deserialize**

Add to `forker.rs`:

```rust
/// Parameters for a worker-exec request, serialized into a memfd.
///
/// Carries the guest identity, arguments, environment, and infrastructure
/// configuration that the worker child needs to boot a new shim and load
/// the non-PIE binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerExecParams {
    /// The resolved binary path (load path for the shim loader).
    pub guest_binary_path: String,
    /// Original guest argv (argv[0] may differ from guest_binary_path for symlinks).
    pub argv: Vec<String>,
    /// Guest environment variables (KEY=VALUE strings).
    pub envp: Vec<String>,
    /// Guest working directory.
    pub cwd: String,
    /// Guest PID.
    pub guest_pid: i32,
    /// Guest parent PID.
    pub guest_ppid: i32,
    /// Guest UID.
    pub guest_uid: u32,
    /// Guest effective UID.
    pub guest_euid: u32,
    /// Guest GID.
    pub guest_gid: u32,
    /// Guest effective GID.
    pub guest_egid: u32,
    /// Path to the interpreter binary (for dynamically-linked non-PIE).
    pub interp_path: Option<String>,
    /// Infrastructure flags forwarded from the runner.
    /// Flat list of (key, value) pairs, e.g. [("--nine-p-broker", "/path")].
    pub infra_flags: Vec<(String, Option<String>)>,
}
```

Wire format: simple length-prefixed strings. Use a `LBWE` magic + version u16 header.

```
"LBWE" (4 bytes) | version u16 LE | guest_binary_path (u32 len + bytes) |
argv_count u32 LE | argv[0] (u32 len + bytes) | ... |
envp_count u32 LE | envp[0] (u32 len + bytes) | ... |
cwd (u32 len + bytes) |
guest_pid i32 LE | guest_ppid i32 LE |
guest_uid u32 LE | guest_euid u32 LE | guest_gid u32 LE | guest_egid u32 LE |
has_interp u8 | [interp_path (u32 len + bytes)] |
infra_flags_count u32 LE | flag_key (u32 len + bytes) | has_value u8 | [value (u32 len + bytes)] | ...
```

Implement `WorkerExecParams::serialize(&self) -> Vec<u8>` and
`WorkerExecParams::deserialize(data: &[u8]) -> Result<Self, &'static str>`.

**Step 2: Add round-trip tests**

```rust
#[test]
fn worker_exec_params_round_trip_minimal() {
    let params = WorkerExecParams {
        guest_binary_path: "/usr/bin/echo".to_string(),
        argv: vec!["echo".to_string(), "hello".to_string()],
        envp: vec!["PATH=/bin".to_string()],
        cwd: "/".to_string(),
        guest_pid: 42,
        guest_ppid: 1,
        guest_uid: 1000,
        guest_euid: 1000,
        guest_gid: 1000,
        guest_egid: 1000,
        interp_path: None,
        infra_flags: vec![],
    };
    let data = params.serialize();
    let decoded = WorkerExecParams::deserialize(&data).unwrap();
    assert_eq!(params, decoded);
}

#[test]
fn worker_exec_params_round_trip_full() {
    let params = WorkerExecParams {
        guest_binary_path: "/usr/bin/node".to_string(),
        argv: vec!["node".to_string(), "index.js".to_string()],
        envp: vec!["PATH=/bin".to_string(), "HOME=/root".to_string()],
        cwd: "/app".to_string(),
        guest_pid: 100,
        guest_ppid: 1,
        guest_uid: 0,
        guest_euid: 0,
        guest_gid: 0,
        guest_egid: 0,
        interp_path: Some("/lib64/ld-linux-x86-64.so.2".to_string()),
        infra_flags: vec![
            ("--nine-p-broker".to_string(), Some("/tmp/broker.sock".to_string())),
            ("--program-from-tar".to_string(), None),
        ],
    };
    let data = params.serialize();
    let decoded = WorkerExecParams::deserialize(&data).unwrap();
    assert_eq!(params, decoded);
}
```

**Step 3: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- worker_exec_params`
Expected: Both tests pass.

**Step 4: Commit**

```
feat(forker): add WorkerExecParams serialization for worker-exec via forker
```

---

### Task 3: Add `try_spawn_worker_exec_via_forker` to LinuxUserland

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs`

**Context:** This is the sender side. It mirrors `try_spawn_via_forker` but builds a
WorkerExec-kind ForkRequest instead of a ForkRestore-kind one. It serializes
`WorkerExecParams` into a memfd, and passes the exec image memfd(s) via SCM_RIGHTS.

**Step 1: Add the method to `impl LinuxUserland`**

Add after `try_spawn_via_forker` (~line 1135):

```rust
/// Attempt to spawn a worker-exec via the forker process.
///
/// Like `try_spawn_via_forker` but for non-PIE execve: the grandchild
/// boots a fresh shim and loads the binary from the exec image memfd.
///
/// Returns `Ok(pid)` on success, `Err(())` if the forker is not available.
#[allow(clippy::too_many_arguments)]
fn try_spawn_worker_exec_via_forker<FS>(
    &'static self,
    guest_binary_path: &str,
    argv: &[alloc::ffi::CString],
    envp: &[alloc::ffi::CString],
    guest_cwd: &str,
    guest_pid: i32,
    guest_ppid: i32,
    guest_uid: u32,
    guest_euid: u32,
    guest_gid: u32,
    guest_egid: u32,
    guest_exec_image: &[u8],
    guest_interp_image: Option<(&str, &[u8])>,
    stdio: &WorkerExecStdioBindings<FS, LinuxUserland>,
) -> Result<i32, ()>
where
    FS: litebox::fs::FileSystem + Send + Sync + 'static,
{
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // 1. Lock forker handle.
    let forker_guard = self.forker_handle.lock().unwrap();
    let forker = match forker_guard.as_ref() {
        Some(h) => h,
        None => return Err(()),
    };

    // 2. Build WorkerExecParams.
    let argv_strings: Vec<String> = argv.iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    let envp_strings: Vec<String> = envp.iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    let infra_flags = {
        let flags = self.worker_spawn_flags.read().unwrap();
        parse_infra_flags_from_cstrings(&flags)
    };
    let params = forker::WorkerExecParams {
        guest_binary_path: guest_binary_path.to_string(),
        argv: argv_strings,
        envp: envp_strings,
        cwd: guest_cwd.to_string(),
        guest_pid,
        guest_ppid,
        guest_uid,
        guest_euid,
        guest_gid,
        guest_egid,
        interp_path: guest_interp_image.map(|(path, _)| path.to_string()),
        infra_flags,
    };

    // 3. Create metadata memfd.
    let params_data = params.serialize();
    let params_fd = create_worker_fork_snapshot_fd(&params_data).map_err(|_| ())?;

    // 4. Create exec image memfd.
    let exec_image_fd = create_worker_exec_image_fd(guest_exec_image).map_err(|_| ())?;

    // 5. Create interp image memfd (optional).
    let interp_image_fd = guest_interp_image
        .map(|(_, image)| create_worker_exec_image_fd(image))
        .transpose()
        .map_err(|_| ())?;

    // 6. Create result pipe.
    let (result_read_fd, result_write_fd) = create_worker_result_pipe().map_err(|_| ())?;

    // 7. Build fds array.
    let mut fds_array: Vec<i32> = Vec::new();
    let mut keep_alive_fds: Vec<OwnedFd> = Vec::new();

    // Index 0: params_fd (metadata memfd)
    let params_fd_idx = fds_array.len() as u8;
    fds_array.push(params_fd.as_raw_fd());

    // Index 1: result_write_fd
    let result_fd_idx = fds_array.len() as u8;
    fds_array.push(result_write_fd.as_raw_fd());

    // Index 2: exec_image_fd
    let exec_image_fd_idx = fds_array.len() as u8;
    fds_array.push(exec_image_fd.as_raw_fd());

    // Index 3: interp_image_fd (optional)
    let interp_image_fd_idx = if let Some(ref interp_fd) = interp_image_fd {
        let idx = fds_array.len() as u8;
        fds_array.push(interp_fd.as_raw_fd());
        idx
    } else {
        0xFF
    };

    // Map stdio bindings.
    let mut stdio_bindings = [forker::StdioBinding::DevNull; 3];
    // stdin
    match &stdio.stdin {
        WorkerExecInputBinding::HostStdio { fd } | WorkerExecInputBinding::HostPipe { fd } => {
            let duped = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duped < 0 { return Err(()); }
            let owned = unsafe { OwnedFd::from_raw_fd(duped) };
            let idx = fds_array.len() as u8;
            fds_array.push(owned.as_raw_fd());
            keep_alive_fds.push(owned);
            stdio_bindings[0] = forker::StdioBinding::FromFdIndex(idx);
        }
        WorkerExecInputBinding::Close => {
            stdio_bindings[0] = forker::StdioBinding::Close;
        }
        _ => {
            stdio_bindings[0] = forker::StdioBinding::DevNull;
        }
    }
    // stdout, stderr
    for (i, binding) in [(1usize, &stdio.stdout), (2usize, &stdio.stderr)] {
        match binding {
            WorkerExecOutputBinding::HostStdio { fd }
            | WorkerExecOutputBinding::HostPipe { fd } => {
                let duped = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 3) };
                if duped < 0 { return Err(()); }
                let owned = unsafe { OwnedFd::from_raw_fd(duped) };
                let idx = fds_array.len() as u8;
                fds_array.push(owned.as_raw_fd());
                keep_alive_fds.push(owned);
                stdio_bindings[i] = forker::StdioBinding::FromFdIndex(idx);
            }
            WorkerExecOutputBinding::Close => {
                stdio_bindings[i] = forker::StdioBinding::Close;
            }
            _ => {
                stdio_bindings[i] = forker::StdioBinding::DevNull;
            }
        }
    }

    // 8. Build ForkRequest.
    #[allow(clippy::cast_possible_truncation)]
    let request = forker::ForkRequest {
        kind: forker::ForkRequestKind::WorkerExec,
        stdio: stdio_bindings,
        num_fds: fds_array.len() as u16,
        snapshot_fd_idx: params_fd_idx,  // repurposed: metadata memfd
        ack_fd_idx: 0xFF,               // worker-exec doesn't use ack
        result_fd_idx,
        mux_fd_idx: 0xFF,
        exec_image_fd_idx,
        interp_image_fd_idx,
        mux_streams: vec![],
        pipe_bridges: vec![],
        local_pipes: vec![],
    };

    // 9. Send fork request.
    let sock_guard = forker.sock.lock().unwrap();
    forker::send_fork_request(sock_guard.as_raw_fd(), &request, &fds_array)
        .map_err(|_| ())?;

    // 10. Receive fork response.
    let response = forker::recv_fork_response(sock_guard.as_raw_fd())
        .map_err(|_| ())?;
    drop(sock_guard);
    drop(forker_guard);

    let child_pid = response.child_pid;
    if child_pid < 0 {
        return Err(());
    }

    // 11. Drop write ends and image fds.
    drop(result_write_fd);
    drop(params_fd);
    drop(exec_image_fd);
    drop(interp_image_fd);
    drop(keep_alive_fds);

    // 12. Register child in worker_processes.
    self.worker_processes.lock().unwrap().insert(
        child_pid,
        WorkerHostProcess {
            result_fd: result_read_fd,
            bridge_threads: Vec::new(),
        },
    );

    Ok(child_pid)
}
```

Also add the helper to parse infra flags from CStrings:

```rust
/// Parse worker spawn flags from CString pairs back into structured form.
fn parse_infra_flags_from_cstrings(
    flags: &[std::ffi::CString],
) -> Vec<(String, Option<String>)> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < flags.len() {
        let key = flags[i].to_string_lossy().into_owned();
        // If next element doesn't start with "--", it's a value
        if i + 1 < flags.len() {
            let next = flags[i + 1].to_string_lossy();
            if !next.starts_with("--") {
                result.push((key, Some(next.into_owned())));
                i += 2;
                continue;
            }
        }
        result.push((key, None));
        i += 1;
    }
    result
}
```

**Step 2: Verify compilation**

Run: `cargo check -p litebox_platform_linux_userland`
Expected: Compiles (the method isn't called yet).

**Step 3: Commit**

```
feat(forker): add try_spawn_worker_exec_via_forker sender
```

---

### Task 4: Extend run_forked_worker callback to handle WorkerExec

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs`

**Context:** The `run_forked_worker` callback currently assumes every request is a
fork-restore. We extend it to check `req.kind` and dispatch to a new
`run_forked_worker_exec` function for `WorkerExec` requests.

**Step 1: Add dispatch at the top of `run_forked_worker`**

In `run_forked_worker` (line ~2543), after converting fds to raw_fds, add:

```rust
// Dispatch based on request kind.
match req.kind {
    litebox_platform_linux_userland::forker::ForkRequestKind::WorkerExec => {
        run_forked_worker_exec(req, raw_fds);
    }
    litebox_platform_linux_userland::forker::ForkRequestKind::ForkRestore => {
        // ... existing fork-restore logic (moved into this branch or a helper) ...
    }
}
```

**Step 2: Write `run_forked_worker_exec`**

This function does what `run_worker_exec` does but reads from memfds instead of CLI args:

```rust
fn run_forked_worker_exec(
    req: litebox_platform_linux_userland::forker::ForkRequest,
    raw_fds: Vec<i32>,
) -> ! {
    use std::os::fd::FromRawFd;
    use litebox_platform_linux_userland::forker::WorkerExecParams;

    let get_fd = |idx: u8| -> Option<i32> {
        if idx == 0xFF { return None; }
        let i = idx as usize;
        if i < raw_fds.len() { Some(raw_fds[i]) } else { None }
    };

    // 1. Read WorkerExecParams from metadata memfd (snapshot_fd_idx).
    let params_fd = get_fd(req.snapshot_fd_idx).unwrap_or(-1);
    if params_fd < 0 {
        unsafe { libc::_exit(1); }
    }
    let params_data = match read_fork_snapshot_from_fd(params_fd) {
        Ok(data) => data,
        Err(_) => unsafe { libc::_exit(1); },
    };
    let params = match WorkerExecParams::deserialize(&params_data) {
        Ok(p) => p,
        Err(_) => unsafe { libc::_exit(1); },
    };

    // 2. Read exec image from memfd.
    let exec_image_fd = get_fd(req.exec_image_fd_idx).unwrap_or(-1);
    if exec_image_fd < 0 {
        unsafe { libc::_exit(1); }
    }
    let exec_image = match read_worker_exec_image(exec_image_fd) {
        Ok(data) => data,
        Err(_) => unsafe { libc::_exit(1); },
    };

    // 3. Read interp image if present.
    let interp_image = if let Some(interp_fd) = get_fd(req.interp_image_fd_idx) {
        match read_worker_exec_image(interp_fd) {
            Ok(data) => Some(data),
            Err(_) => unsafe { libc::_exit(1); },
        }
    } else {
        None
    };

    // 4. Get result_fd.
    let result_fd = get_fd(req.result_fd_idx);
    if let Some(fd) = result_fd {
        let _ = set_fd_cloexec(fd);
    }

    // 5. Close remaining SCM_RIGHTS fds that we no longer need.
    for (i, &fd) in raw_fds.iter().enumerate() {
        let i_u8 = i as u8;
        if i_u8 == req.snapshot_fd_idx { continue; } // closed by read_fork_snapshot_from_fd
        if i_u8 == req.exec_image_fd_idx { continue; } // closed by read_worker_exec_image
        if i_u8 == req.interp_image_fd_idx { continue; } // closed by read_worker_exec_image
        if i_u8 == req.result_fd_idx { continue; } // still needed
        // Stdio source fds were already dup2'd by worker_entry.
        let is_stdio_source = req.stdio.iter().any(|b| {
            matches!(b, litebox_platform_linux_userland::forker::StdioBinding::FromFdIndex(idx) if *idx == i_u8)
        });
        if is_stdio_source {
            unsafe { libc::close(fd); }
            continue;
        }
        unsafe { libc::close(fd); }
    }

    // 6. Build CliArgs-equivalent from params and run worker exec logic.
    //    This mirrors run_worker_exec but uses deserialized params instead of CLI args.
    let cli_args = build_cli_args_from_exec_params(&params, result_fd);

    // 7. Inject exec image into in-memory FS and run.
    if let Err(_) = run_worker_exec_from_images(
        cli_args,
        exec_image,
        interp_image.as_deref().map(|d| {
            (params.interp_path.as_deref().unwrap_or(""), d)
        }),
    ) {
        unsafe { libc::_exit(1); }
    }
}
```

**Step 3: Add `build_cli_args_from_exec_params` helper**

This builds a `CliArgs` from `WorkerExecParams` — mirrors what the CLI parser would
produce from `--worker-exec` flags:

```rust
fn build_cli_args_from_exec_params(
    params: &litebox_platform_linux_userland::forker::WorkerExecParams,
    result_fd: Option<i32>,
) -> CliArgs {
    // Reconstruct infra flags into CliArgs fields.
    let mut nine_p_broker = None;
    let mut network_broker = None;
    let mut tun_device_name = None;
    let mut initial_files = None;
    let mut program_from_tar = false;

    for (key, value) in &params.infra_flags {
        match key.as_str() {
            "--nine-p-broker" => nine_p_broker = value.clone(),
            "--network-broker" => network_broker = value.clone(),
            "--tun-device-name" => tun_device_name = value.clone(),
            "--initial-files" => initial_files = value.as_ref().map(PathBuf::from),
            "--program-from-tar" => program_from_tar = true,
            _ => {}
        }
    }

    // program_and_arguments: [0] = guest_binary_path, [1..] = argv
    let mut program_and_arguments = vec![params.guest_binary_path.clone()];
    program_and_arguments.extend(params.argv.iter().cloned());

    CliArgs {
        program_and_arguments,
        environment_variables: params.envp.clone(),
        forward_environment_variables: false,
        unstable: true,
        insert_files: vec![],
        initial_files,
        rewrite_syscalls: false,
        interception_backend: InterceptionBackend::Rewriter,
        tun_device_name,
        network_broker,
        program_from_tar,
        nine_p_broker,
        working_directory: Some(params.cwd.clone()),
        worker_exec: true,
        worker_exec_fd: None,  // image is passed directly, not via fd
        worker_result_fd: result_fd,
        worker_interp_fd: None,
        worker_interp_path: params.interp_path.clone(),
        guest_pid: Some(params.guest_pid),
        guest_ppid: Some(params.guest_ppid),
        guest_uid: Some(params.guest_uid),
        guest_euid: Some(params.guest_euid),
        guest_gid: Some(params.guest_gid),
        guest_egid: Some(params.guest_egid),
        fork_restore: false,
        fork_restore_fd: None,
        fork_restore_ack_fd: None,
        pipe_bridge: vec![],
        mux_fd: None,
        mux_stream: vec![],
        local_pipe: vec![],
    }
}
```

**Step 4: Add `run_worker_exec_from_images` helper**

This is `run_worker_exec` but takes the exec image bytes directly instead of reading
from a memfd:

```rust
fn run_worker_exec_from_images(
    cli_args: CliArgs,
    exec_image: alloc::borrow::Cow<'static, [u8]>,
    interp_image: Option<(&str, &[u8])>,
) -> Result<()> {
    // This is the same as run_worker_exec starting from line ~1804
    // but uses the provided exec_image instead of reading from worker_exec_fd.
    // Extract most of run_worker_exec into a shared helper that both paths call.
    // ... (see implementation notes below)
}
```

**Implementation notes:** The cleanest approach is to refactor `run_worker_exec` to
extract its core logic into a shared helper:

```rust
fn run_worker_exec_core(
    cli_args: CliArgs,
    transferred_exec_image: Option<alloc::borrow::Cow<'static, [u8]>>,
    transferred_interp_image: Option<(&str, alloc::borrow::Cow<'static, [u8]>)>,
) -> Result<()>
```

Then `run_worker_exec` reads from fds and calls `run_worker_exec_core`.
And `run_forked_worker_exec` passes images directly to `run_worker_exec_core`.

**Step 5: Verify compilation**

Run: `cargo check -p litebox_runner_linux_userland`

**Step 6: Commit**

```
feat(forker): handle WorkerExec requests in forked worker callback
```

---

### Task 5: Wire `spawn_worker_host_for_exec` to try forker first

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs`

**Context:** This is the final wiring. `spawn_worker_host_for_exec` (~line 1422) currently
goes straight to `posix_spawn`. We add a "try forker first" attempt at the top, before
the existing posix_spawn code. If the forker succeeds, we skip posix_spawn but still
need to set up bridge threads (the stdio bridge logic after posix_spawn is shared).

**Step 1: Restructure `spawn_worker_host_for_exec`**

At the top of the function, after `_spawn_guard` and `reap_finished_worker_bridge_threads()`:

```rust
// Try the forker path first (no execve, no openat).
if let Ok(pid) = self.try_spawn_worker_exec_via_forker(
    guest_binary_path,
    argv,
    envp,
    guest_cwd,
    guest_pid,
    guest_ppid,
    guest_uid,
    guest_euid,
    guest_gid,
    guest_egid,
    guest_exec_image,
    guest_interp_image,
    &stdio,
) {
    // Forker succeeded — we have a child PID. The child's stdio was wired
    // by the forker (simple bindings only). Complex bindings (Fs/Pipe/Stream)
    // still need bridge threads, but the forker path currently handles only
    // simple HostStdio/HostPipe/Close/Inherit bindings.
    //
    // For now, if the caller has complex stdio bindings, the forker path
    // maps them to DevNull and the bridge threads don't apply.
    // TODO: add bridge pipe support for forker worker-exec.
    return Ok(WorkerExecSpawnResult {
        host_pid: pid,
        direct_pipes: vec![],
    });
}
// Fall through to posix_spawn path.
```

This means the forker path handles the simple case (which covers the vast majority of
exec calls). Complex stdio bindings still fall through to posix_spawn until bridge
pipe support is added.

**Step 2: Verify compilation**

Run: `cargo check -p litebox_platform_linux_userland`

**Step 3: Build and test**

Run: `cargo build -p litebox_runner_oci -p litebox_broker --release`
Run: `cargo test -p litebox_platform_linux_userland -- forker`
Run: `cargo test -p litebox_runner_linux_userland --lib`

**Step 4: Commit**

```
feat(forker): route worker-exec through forker, eliminating posix_spawn for non-PIE execve
```

---

### Task 6: Integration test — OCI runner with shell script

**Files:**
- None (test via shell commands)

**Step 1: Build**

Run: `cargo build -p litebox_runner_oci -p litebox_broker --release`

**Step 2: Test simple echo**

```bash
# Create test bundle with host-matching rootfs layout
mkdir -p /tmp/test-bundle/rootfs/{usr/bin,tmp,dev,proc}
cp /bin/busybox /tmp/test-bundle/rootfs/usr/bin/busybox
for cmd in echo sh ls head cat; do
    ln -sf busybox /tmp/test-bundle/rootfs/usr/bin/$cmd
done
rm -f /tmp/test-bundle/rootfs/bin
ln -sf usr/bin /tmp/test-bundle/rootfs/bin

cat > /tmp/test-bundle/config.json << 'EOF'
{
    "ociVersion": "1.0.0",
    "root": { "path": "rootfs" },
    "process": {
        "args": ["/bin/echo", "Hello from LiteBox OCI with fork!"],
        "env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
        "cwd": "/",
        "user": { "uid": 0, "gid": 0 }
    }
}
EOF

./target/release/litebox_runner_oci run --bundle /tmp/test-bundle test-echo
```

Expected: `Hello from LiteBox OCI with fork!`

**Step 3: Test shell script (exercises fork+exec through forker)**

```bash
cat > /tmp/test-bundle/config.json << 'EOF'
{
    "ociVersion": "1.0.0",
    "root": { "path": "rootfs" },
    "process": {
        "args": ["/usr/bin/busybox", "sh", "-c",
                 "echo parent: $$ && /usr/bin/busybox ls / && echo done"],
        "env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
        "cwd": "/",
        "user": { "uid": 0, "gid": 0 }
    }
}
EOF

./target/release/litebox_runner_oci run --bundle /tmp/test-bundle test-shell
```

Expected: Lists root directory contents, prints "done".

**Step 4: Verify no posix_spawn of runner binary**

```bash
strace -f -e trace=execve ./target/release/litebox_runner_oci run \
    --bundle /tmp/test-bundle test-strace 2>&1
```

Expected: Only `execve` of the initial litebox_runner_oci binary, NO re-exec of
`/proc/self/exe` for worker-exec.

**Step 5: Commit**

```
test(oci): verify shell script works with fork+exec through forker
```

---

### Task 7: Polish — clippy, all tests, OCI runner fixes

**Step 1: Run all unit tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Run: `cargo test -p litebox_runner_linux_userland --lib`
Run: `cargo test -p litebox_runner_oci --lib`

**Step 2: Run clippy**

Run: `cargo clippy -p litebox_platform_linux_userland -p litebox_runner_linux_userland -p litebox_runner_oci`
Expected: No warnings.

**Step 3: Commit**

```
chore: clippy fixes and polish for worker-exec via forker
```
