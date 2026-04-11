# OCI Fixes and 9P Bind Mount Support

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix two critical OCI runtime bugs (stdout pollution, exit code propagation) and add bind mount support to the 9P broker so the OCI runner can serve additional host directories at arbitrary guest paths.

**Architecture:** (1) Remove erroneous `println!` from create/start. (2) Change `run()` from diverging (`process::exit`) to returning `Result<i32>`, cascading through `run_program` → `finish_run` → `run()`. (3) Add a `MountTable` to the 9P broker's `Server` that maps guest-relative prefixes to host directories, consulted during `handle_walk` and `handle_readdir`. (4) Wire OCI `config.json` mounts into broker `--bind` flags.

**Tech Stack:** Rust, 9P2000.L, OCI runtime spec, clap CLI

---

## Task 1: Remove stdout pollution from `create` and `start`

The OCI spec says only `state` should print JSON to stdout. `runc` does not print on create/start. Our runtime does, which can confuse containerd/Podman.

**Files:**
- Modify: `litebox_runner_oci/src/main.rs:316` and `main.rs:324`

**Step 1: Remove the println from create**

In `main.rs`, line 316, remove:
```rust
            println!("{}", serde_json::to_string_pretty(&state)?);
```

**Step 2: Remove the println from start**

In `main.rs`, line 324, remove:
```rust
            println!("{}", serde_json::to_string_pretty(&state)?);
```

**Step 3: Build and test**

Run: `cargo build -p litebox_runner_oci`
Run: `cargo test -p litebox_runner_oci --lib`
Expected: 49 tests pass, clean build.

**Step 4: Commit**

```bash
git add litebox_runner_oci/src/main.rs
git commit -m "fix(oci): remove stdout pollution from create and start commands"
```

---

## Task 2: Make `run()` return exit code instead of diverging

Currently `run_program()` calls `terminate_host_with_guest_wait_status()` which calls `std::process::exit()`, so `run()` never returns. This means:
- The OCI runner can't clean up the broker process
- The exit code return path in `run_container` is dead code

Change the call chain so `run()` returns `Result<i32>` with the exit code.

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs`

**Important context:**
- `run_program` is `-> !` because it ends with `terminate_host_with_guest_wait_status(wait_status)` which is `-> !`
- `run_thread()` already returns normally (NOT `-> !`)
- `process.wait()` returns an `i32` wait_status (litebox encoding: 0-255 = exit code, 256+ = signal + 256)
- Forked worker paths (`run_forked_worker`, `run_forked_worker_exec`) run in separate OS processes and should KEEP calling `terminate_host_with_guest_wait_status()` — they're not in the `run()` call chain
- `worker_result_fd` writes: forked workers write their result to a pipe fd before exiting. This must be preserved.

**Step 1: Add a helper to convert wait_status to host exit code**

Add near `terminate_host_with_guest_wait_status` (~line 993):

```rust
/// Convert a litebox guest wait_status into a conventional host exit code.
///
/// Normal exit: pass through the exit code (0–255).
/// Signal death: return 128 + signal number (shell convention).
fn guest_wait_status_to_exit_code(wait_status: i32) -> i32 {
    if wait_status > 255 {
        let signal = wait_status - 256;
        128 + signal
    } else {
        wait_status
    }
}
```

**Step 2: Change `run_program` from `-> !` to `-> i32`**

At `run_program` (~line 1999):
- Change return type from `-> !` to `-> i32`
- Replace the final `terminate_host_with_guest_wait_status(wait_status)` with `guest_wait_status_to_exit_code(wait_status)`
- Keep the `write_worker_result` call for forked workers (it writes before we return)

**Step 3: Change `finish_run` from `-> Result<()>` to `-> Result<i32>`**

Find all `run_program(...)` calls in `finish_run` and wrap them: `Ok(run_program(...))`

**Step 4: Change `finish_run_with_nine_p` from `-> Result<()>` to `-> Result<i32>`**

Same pattern — wrap `run_program(...)` calls with `Ok(...)`.

**Step 5: Change `run_worker_exec_core` from `-> Result<()>` to `-> Result<i32>`**

Wrap `run_program(...)` calls with `Ok(...)`.

**Step 6: Change `run_worker_exec` from `-> Result<()>` to `-> Result<i32>`**

Propagate from `run_worker_exec_core`.

**Step 7: Change `run_fork_restore` from `-> Result<()>` to `-> Result<i32>`**

Wrap `run_program(...)` calls with `Ok(...)`.

**Step 8: Change `pub fn run` from `-> Result<()>` to `-> Result<i32>`**

The three branches already call the changed functions and will propagate the `i32`.

**Step 9: IMPORTANT — keep `terminate_host_with_guest_wait_status` for forked workers**

Do NOT remove `terminate_host_with_guest_wait_status`. It is still called by forked worker processes (`run_forked_worker`, `run_forked_worker_exec`) which run in separate OS processes and must call `process::exit()` / `_exit()`.

**Step 10: Update OCI runner to use the exit code**

In `litebox_runner_oci/src/runner.rs`, update `run_container`:
- Line 559: `litebox_runner_linux_userland::run(cli_args)` now returns `Result<i32>`
- Line 567: `Ok(()) => Ok(0)` becomes `Ok(exit_code) => Ok(exit_code)`
- The broker cleanup code (lines 562-564) now actually runs!

Also update `litebox_runner_oci/src/main.rs`:
- The `Run` command handler uses `run_container(...)` return value for `process::exit(exit_code)`

**Step 11: Build and test**

Run: `cargo build -p litebox_runner_linux_userland -p litebox_runner_oci`
Run: `cargo test -p litebox_runner_linux_userland --lib`
Run: `cargo test -p litebox_runner_oci --lib`
Expected: All tests pass, clean build, no warnings.

**Step 12: Commit**

```bash
git add litebox_runner_linux_userland/src/lib.rs litebox_runner_oci/src/runner.rs litebox_runner_oci/src/main.rs
git commit -m "fix(runner): return exit code from run() instead of calling process::exit

Change run() signature from Result<()> to Result<i32>, cascading through
run_program, finish_run, run_worker_exec, and run_fork_restore. The OCI
runner now receives the actual container exit code and can clean up the
broker process before exiting.

Forked worker paths (separate OS processes) still use
terminate_host_with_guest_wait_status() to exit directly."
```

---

## Task 3: Add `--bind` flag and `MountTable` to the 9P broker

Add a mount table that maps guest-relative path prefixes to host directories. During walk, when the resolved guest-relative path matches a mount point, redirect to the mounted host path.

**Files:**
- Modify: `litebox_broker/src/nine_p/server.rs` — `Server` struct, `handle_walk`, `handle_readdir`, `resolve_and_check`, `resolve_fid_path`
- Modify: `litebox_broker/src/main.rs` — add `--bind` CLI flag
- Create: `litebox_broker/src/nine_p/mount_table.rs` — mount point resolution logic

**Step 1: Create MountTable type**

Create `litebox_broker/src/nine_p/mount_table.rs`:

```rust
use std::path::{Path, PathBuf};

/// Maps guest-relative path prefixes to host directory paths.
///
/// When the 9P server walks into a guest path that matches a mount point,
/// the walk redirects into the mounted host directory instead of the
/// server's root directory.
///
/// Mount points are sorted longest-prefix-first so that nested mounts
/// (e.g., `/etc` and `/etc/app`) resolve correctly.
#[derive(Debug, Clone)]
pub struct MountTable {
    /// Sorted longest-prefix-first: `(guest_prefix, host_path)`.
    mounts: Vec<(PathBuf, PathBuf)>,
}

impl MountTable {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Add a bind mount: guest paths under `guest_prefix` resolve to
    /// `host_path` instead of `root/guest_prefix`.
    ///
    /// `guest_prefix` must be a relative path (no leading `/`).
    /// `host_path` must be an absolute, canonicalized host path.
    pub fn add(&mut self, guest_prefix: PathBuf, host_path: PathBuf) {
        self.mounts.push((guest_prefix, host_path));
        // Sort longest-prefix-first for correct nested mount resolution.
        self.mounts.sort_by(|a, b| b.0.components().count().cmp(&a.0.components().count()));
    }

    /// Check if `guest_relative_path` falls under a mount point.
    ///
    /// Returns `Some(host_path)` where `host_path` is the fully resolved
    /// host path for the guest path, or `None` if no mount matches.
    pub fn resolve(&self, guest_relative_path: &Path) -> Option<PathBuf> {
        for (prefix, host_target) in &self.mounts {
            if let Ok(suffix) = guest_relative_path.strip_prefix(prefix) {
                if suffix == Path::new("") {
                    return Some(host_target.clone());
                }
                return Some(host_target.join(suffix));
            }
        }
        None
    }

    /// Return mount points whose parent is `guest_relative_dir`.
    ///
    /// Used by `handle_readdir` to inject mount point entries into
    /// directory listings.
    pub fn children_of(&self, guest_relative_dir: &Path) -> Vec<&Path> {
        self.mounts
            .iter()
            .filter_map(|(prefix, _)| {
                let parent = prefix.parent()?;
                if parent == guest_relative_dir {
                    // Return just the final component name as a Path
                    Some(prefix.file_name().map(Path::new)?)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }

    /// Check if a host path is under any mount target.
    pub fn is_under_mount(&self, host_path: &Path) -> bool {
        self.mounts.iter().any(|(_, target)| host_path.starts_with(target))
    }
}
```

**Step 2: Add MountTable to Server**

In `server.rs`, add `mount_table: MountTable` field to `Server` struct. Update constructors (`new`, `with_elf_cache`) to accept an optional `MountTable` parameter. Default to empty.

**Step 3: Modify `handle_walk` to consult mount table**

In `handle_walk` (~line 699), after computing `next = current_path.join(component)`:

1. Compute the guest-relative path: `next.strip_prefix(&self.root)` (only when `next` starts with `self.root`)
2. Check `self.mount_table.resolve(guest_relative)`:
   - If `Some(host_path)`: use `host_path` as the walk target instead of `next`
   - If `None`: proceed as before
3. Expand the containment check (line 740) to also accept paths under mount targets:
   ```rust
   if !resolved.starts_with(&self.root) && !self.mount_table.is_under_mount(&resolved) {
       break;
   }
   ```

**Step 4: Modify `handle_readdir` to inject mount entries**

In `handle_readdir` (~line 1224), after iterating `fs::read_dir(&path)`:

1. Compute guest-relative path of the directory
2. Get mount children via `self.mount_table.children_of(guest_relative)`
3. For each mount child name that wasn't already in the real directory listing, inject a synthetic `DirEntry` with `DT_DIR` type

**Step 5: Modify `resolve_and_check` and `resolve_fid_path`**

Expand containment checks to accept mount target paths:
```rust
fn resolve_and_check(&self, path: &Path) -> Result<PathBuf, u32> {
    let canonical = fs::canonicalize(path).map_err(io_errno)?;
    if canonical.starts_with(&self.root) || self.mount_table.is_under_mount(&canonical) {
        Ok(canonical)
    } else {
        Err(libc::EPERM as u32)
    }
}
```

**Step 6: Add `--bind` CLI flag to broker**

In `litebox_broker/src/main.rs`, add:
```rust
    /// Bind mount a host directory at a guest path (read-only).
    /// Format: guest_path:host_path (e.g., /etc/resolv.conf:/run/host-resolv.conf)
    #[arg(long = "bind")]
    binds: Vec<String>,
```

Parse each bind spec into `(guest_prefix, host_path)` and build a `MountTable`. Pass it to `Server::new()` / `Server::with_elf_cache()`.

**Step 7: Add tests for MountTable**

Add unit tests in `mount_table.rs`:
- `resolve_exact_match` — `/mnt/data` matches mount at `/mnt/data`
- `resolve_subpath` — `/mnt/data/file.txt` resolves under mount
- `resolve_no_match` — `/other/path` returns None
- `resolve_nested_mounts` — longer prefix wins over shorter
- `children_of` — returns mount point names under a directory
- `is_under_mount` — checks host paths correctly

**Step 8: Build and test**

Run: `cargo build -p litebox_broker`
Run: `cargo test -p litebox_broker`
Expected: All tests pass.

**Step 9: Commit**

```bash
git add litebox_broker/src/nine_p/mount_table.rs litebox_broker/src/nine_p/server.rs litebox_broker/src/nine_p/mod.rs litebox_broker/src/main.rs
git commit -m "feat(broker): add bind mount support via --bind flag and MountTable

Add MountTable to the 9P server that maps guest-relative path prefixes
to host directories. During walk, paths matching a mount point are
redirected to the mounted host directory. Directory listings (readdir)
inject mount point entries. All bind mounts are read-only.

CLI: --bind guest_path:host_path (can be specified multiple times)"
```

---

## Task 4: Wire OCI `config.json` mounts into broker `--bind` flags

Parse the `mounts` array from `config.json` and pass relevant entries as `--bind` flags to the broker.

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs` — `spawn_broker`, `run_container`

**Step 1: Parse mounts from OCI spec**

In `run_container`, after loading the spec, extract bind mounts:

```rust
let bind_mounts: Vec<(String, String)> = spec.mounts().as_ref()
    .map(|mounts| mounts.iter()
        .filter(|m| {
            // Include bind mounts and mounts with a real source path
            let typ = m.typ().as_deref().unwrap_or("bind");
            typ == "bind" || typ == "none"
        })
        .filter_map(|m| {
            let source = m.source().as_ref()?.to_str()?;
            let dest = m.destination().to_str()?;
            // Strip leading / from dest for guest-relative path
            let guest_path = dest.strip_prefix('/').unwrap_or(dest);
            Some((guest_path.to_string(), source.to_string()))
        })
        .collect())
    .unwrap_or_default();
```

**Step 2: Pass bind mounts to `spawn_broker`**

Update `spawn_broker` signature to accept `&[(String, String)]` bind mounts. Add `--bind` args:

```rust
for (guest_path, host_path) in bind_mounts {
    cmd.arg("--bind");
    cmd.arg(format!("{}:{}", guest_path, host_path));
}
```

**Step 3: Build and test**

Run: `cargo build -p litebox_runner_oci`
Run: `cargo test -p litebox_runner_oci --lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add litebox_runner_oci/src/runner.rs
git commit -m "feat(oci): translate config.json bind mounts into broker --bind flags"
```

---

## Task 5: Add `--writable-path` passthrough from OCI config

Currently `/tmp` and `/var` are hardcoded as writable paths. Allow OCI config to control this.

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs` — `spawn_broker`

**Step 1: Parse writable tmpfs mounts from OCI spec**

OCI specs commonly include tmpfs mounts like `{"destination": "/tmp", "type": "tmpfs"}`. These should map to broker `--writable-path` flags:

```rust
let writable_paths: Vec<String> = spec.mounts().as_ref()
    .map(|mounts| mounts.iter()
        .filter(|m| m.typ().as_deref() == Some("tmpfs"))
        .filter_map(|m| m.destination().to_str().map(String::from))
        .collect())
    .unwrap_or_else(|| vec!["/tmp".to_string(), "/var".to_string()]);
```

**Step 2: Pass to broker**

Replace hardcoded `/tmp` and `/var` with the parsed writable paths.

**Step 3: Build and test**

Run: `cargo build -p litebox_runner_oci`
Run: `cargo test -p litebox_runner_oci --lib`

**Step 4: Commit**

```bash
git add litebox_runner_oci/src/runner.rs
git commit -m "feat(oci): parse tmpfs mounts as writable paths instead of hardcoding /tmp and /var"
```

---

## Task 6: Integration test

**Step 1: Build everything**

```bash
cargo build -p litebox_runner_oci -p litebox_broker -p litebox_runner_linux_userland
```

**Step 2: Run Alpine stress test**

```bash
timeout 30 ./target/debug/litebox_runner_linux_userland -Z \
  --initial-files /tmp/alpine-test/alpine.tar \
  --program-from-tar --interception-backend rewriter \
  /bin/sh -c 'echo hello; result=$(echo world); echo "got: $result"; exit 42'
```

Verify:
- Output contains `hello` and `got: world`
- **Exit code is 42** (not 0)

**Step 3: Commit plan docs**

```bash
git add docs/plans/2026-04-11-oci-fixes-and-bind-mounts.md
git commit -m "docs: add plan for OCI fixes and 9P bind mount support"
```
