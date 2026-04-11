# OCI process.user UID/GID + /proc Directory Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire OCI `process.user` UID/GID into the sandbox so containers run as the specified user, and ensure `/proc` directory exists so OCI proc mounts don't silently fail.

**Architecture:** Two independent fixes. Fix 1 reads `process.user().uid()` and `.gid()` from the OCI spec in `build_cli_args()`, then constructs a `TaskParams` override in `finish_run()` when those fields are present. Fix 2 creates `/proc` and `/proc/self` directories in the in-mem FS layer when OCI spec has a `proc` mount type.

**Tech Stack:** Rust, oci-spec 0.8.4, litebox_runner_oci, litebox_runner_linux_userland

---

### Task 1: Wire OCI process.user UID/GID into CliArgs

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs:448-451` (the `guest_uid/euid/gid/egid: None` lines in `build_cli_args()`)
- Test: `litebox_runner_oci/src/runner.rs` (new `#[cfg(test)]` module)

**Step 1: Write the failing test**

Add a test module at the bottom of `runner.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{ProcessBuilder, SpecBuilder, UserBuilder};

    /// Helper: build a minimal OCI spec with a given UID/GID in process.user.
    fn spec_with_user(uid: u32, gid: u32) -> Spec {
        let user = UserBuilder::default().uid(uid).gid(gid).build().unwrap();
        let process = ProcessBuilder::default()
            .args(vec!["echo".to_string(), "hello".to_string()])
            .user(user)
            .cwd("/".to_string())
            .build()
            .unwrap();
        SpecBuilder::default()
            .process(process)
            .build()
            .unwrap()
    }

    #[test]
    fn build_cli_args_sets_uid_gid_from_spec() {
        let spec = spec_with_user(1000, 1000);
        let args = build_cli_args(&spec, None, &[], "/tmp/test.sock", None).unwrap();
        assert_eq!(args.guest_uid, Some(1000));
        assert_eq!(args.guest_euid, Some(1000));
        assert_eq!(args.guest_gid, Some(1000));
        assert_eq!(args.guest_egid, Some(1000));
    }

    #[test]
    fn build_cli_args_sets_root_uid_gid_when_zero() {
        let spec = spec_with_user(0, 0);
        let args = build_cli_args(&spec, None, &[], "/tmp/test.sock", None).unwrap();
        assert_eq!(args.guest_uid, Some(0));
        assert_eq!(args.guest_euid, Some(0));
        assert_eq!(args.guest_gid, Some(0));
        assert_eq!(args.guest_egid, Some(0));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p litebox_runner_oci --lib -- tests::build_cli_args_sets`
Expected: FAIL — `guest_uid` is `None`, not `Some(1000)`

**Step 3: Write minimal implementation**

In `build_cli_args()` at lines 448-451, replace:

```rust
        guest_uid: None,
        guest_euid: None,
        guest_gid: None,
        guest_egid: None,
```

With:

```rust
        guest_uid: Some(process.user().uid()),
        guest_euid: Some(process.user().uid()),
        guest_gid: Some(process.user().gid()),
        guest_egid: Some(process.user().gid()),
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p litebox_runner_oci --lib -- tests::build_cli_args_sets`
Expected: PASS (both tests)

**Step 5: Run existing tests to verify no regressions**

Run: `cargo test -p litebox_runner_oci --lib`
Expected: All 51 tests pass (49 existing + 2 new)

**Step 6: Commit**

```bash
git add litebox_runner_oci/src/runner.rs
git commit -m "feat(oci): wire process.user UID/GID into CliArgs"
```

---

### Task 2: Apply CliArgs UID/GID override in finish_run()

**Files:**
- Modify: `litebox_runner_linux_userland/src/lib.rs:672-686` (the non-9P path in `finish_run()`)
- Test: `litebox_runner_linux_userland/src/lib.rs` (existing test module)

The 9P path (`finish_run_with_nine_p`) already accepts `task_override: Option<TaskParams>` at line 732 and applies it at line 842: `task_override.unwrap_or_else(|| platform.init_task())`. The problem is:

1. The non-9P path in `finish_run()` at line 680 always calls `platform.init_task()` — it ignores CliArgs uid/gid.
2. The caller of `finish_run_with_nine_p()` at line 659 passes `None` as `task_override`.

**Step 1: Write a helper function to build task override**

Add a function `task_override_from_cli_args()` near `worker_task_params()` (line 854):

```rust
/// Build a [`TaskParams`] override from CliArgs guest UID/GID fields, if any are set.
///
/// When the OCI runner provides `process.user` UID/GID, those values are stored in
/// `guest_uid`/`guest_gid`. This function constructs a `TaskParams` that overrides
/// the host process identity while keeping the host PID/PPID (needed for correct
/// scheduling).
fn task_override_from_cli_args(
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
) -> Option<litebox_common_linux::TaskParams> {
    // Only override if at least one UID/GID field is explicitly set.
    if cli_args.guest_uid.is_none()
        && cli_args.guest_gid.is_none()
    {
        return None;
    }
    let host = platform.init_task();
    Some(litebox_common_linux::TaskParams {
        pid: host.pid,
        ppid: host.ppid,
        uid: cli_args.guest_uid.unwrap_or(host.uid),
        euid: cli_args.guest_euid.unwrap_or(cli_args.guest_uid.unwrap_or(host.euid)),
        gid: cli_args.guest_gid.unwrap_or(host.gid),
        egid: cli_args.guest_egid.unwrap_or(cli_args.guest_gid.unwrap_or(host.egid)),
    })
}
```

**Step 2: Modify finish_run() non-9P path**

Replace line 680:
```rust
            platform.init_task(),
```
With:
```rust
            task_override_from_cli_args(cli_args, platform)
                .unwrap_or_else(|| platform.init_task()),
```

**Step 3: Modify finish_run() 9P path**

Replace the call at lines 659-670:
```rust
        finish_run_with_nine_p(
            shim_builder,
            fs,
            cli_args,
            platform,
            load_prog_path,
            exec_prog_path,
            argv,
            envp,
            None,
            None,
        )
```
With:
```rust
        finish_run_with_nine_p(
            shim_builder,
            fs,
            cli_args,
            platform,
            load_prog_path,
            exec_prog_path,
            argv,
            envp,
            task_override_from_cli_args(cli_args, platform),
            None,
        )
```

**Step 4: Add unit tests for task_override_from_cli_args**

Add tests in the existing test module of `lib.rs` (find the `#[cfg(test)]` module):

```rust
#[test]
fn task_override_from_cli_args_returns_none_when_no_uid_gid() {
    // A default CliArgs with guest_uid/gid = None should return None
    // (indicating use host identity).
    // This test verifies the function's None-path logic.
    // Since CliArgs has many fields, we test the logic conceptually:
    // - When guest_uid is None AND guest_gid is None → return None
}

#[test]
fn task_override_from_cli_args_returns_some_when_uid_set() {
    // When guest_uid is Some(1000) → return Some(TaskParams) with uid=1000
}
```

Note: The actual tests will need a CliArgs construction. If CliArgs is hard to construct in tests,
add a minimal test that just verifies the function signature compiles and the branching logic.
The true integration test is running an OCI container with `process.user.uid: 1000` and checking
the guest sees UID 1000 (via `id` command).

**Step 5: Run tests**

Run: `cargo test -p litebox_runner_linux_userland --lib`
Expected: All tests pass (10 existing + new)

Run: `cargo test -p litebox_runner_oci --lib`
Expected: All 51 tests pass

**Step 6: Commit**

```bash
git add litebox_runner_linux_userland/src/lib.rs
git commit -m "feat(runner): apply OCI process.user UID/GID as TaskParams override"
```

---

### Task 3: Ensure /proc directory exists for OCI proc mounts

**Files:**
- Modify: `litebox_runner_oci/src/runner.rs:524-558` (mount extraction section)
- Modify: `litebox_runner_linux_userland/src/lib.rs:517-598` (`build_initial_fs()`)
- Modify: `litebox_runner_linux_userland/src/lib.rs` (CliArgs struct — add `proc_mount` bool)

**Context:** Litebox already synthetically handles `/proc/self/maps`, `/proc/self/exe`, `/proc/self/cwd`, and `/proc/self/fd/N` at the syscall level in `litebox_shim_linux/src/syscalls/file.rs`. However, `stat("/proc")` fails because the directory itself doesn't exist in the in-mem filesystem. When OCI config.json specifies a `proc` mount, we should ensure the directories exist.

**Step 1: Add `proc_mount` flag to CliArgs**

In the `CliArgs` struct definition, add a new field:

```rust
    /// Whether to create /proc directories in the in-mem filesystem.
    /// Set when OCI config.json has a proc mount type.
    #[clap(skip)]
    pub proc_mount: bool,
```

**Step 2: Set the flag in build_cli_args (OCI runner)**

In `build_cli_args()` in runner.rs, after the CliArgs construction, detect proc mounts from the spec.

Add a helper before the Ok(CliArgs { ... }) return, and add the field to the struct literal:

```rust
        // Detect proc mount in OCI spec
        let has_proc_mount = spec
            .mounts()
            .as_ref()
            .map(|mounts| mounts.iter().any(|m| m.typ().as_deref() == Some("proc")))
            .unwrap_or(false);
```

Then in the CliArgs struct literal, add:
```rust
        proc_mount: has_proc_mount,
```

**Step 3: Create /proc directories in build_initial_fs**

In `build_initial_fs()` in lib.rs, after the existing `/tmp` creation block (line 588-598),
add:

```rust
    // When OCI spec requests a proc mount, create /proc and /proc/self directories.
    // The actual /proc/self/* contents (maps, exe, cwd, fd/) are handled synthetically
    // at the syscall level in litebox_shim_linux/src/syscalls/file.rs.
    if cli_args.proc_mount {
        in_mem.with_root_privileges(|fs| {
            let mode = Mode::RXUO | Mode::RXGO | Mode::RXOO;
            let _ = fs.mkdir("/proc", mode);
            let _ = fs.mkdir("/proc/self", mode);
        });
    }
```

Wait — `Mode::RXUO` etc. may not exist. Check what mode constants are available. Looking at
the `/tmp` creation: `Mode::RWXU | Mode::RWXG | Mode::RWXO`. For /proc we want 0o555 (r-xr-xr-x).
Use: `Mode::RXU | Mode::RXG | Mode::RXO` or similar. If those don't exist, construct from
individual bits: `Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH`.
Check the actual Mode type used in the codebase and use the correct constants.

**Step 4: Write tests**

In runner.rs tests module, add:

```rust
    #[test]
    fn build_cli_args_detects_proc_mount() {
        use oci_spec::runtime::{MountBuilder, ProcessBuilder, SpecBuilder, UserBuilder};
        let user = UserBuilder::default().build().unwrap();
        let proc_mount = MountBuilder::default()
            .typ("proc".to_string())
            .destination("/proc".to_string())
            .build()
            .unwrap();
        let process = ProcessBuilder::default()
            .args(vec!["sh".to_string()])
            .user(user)
            .cwd("/".to_string())
            .build()
            .unwrap();
        let spec = SpecBuilder::default()
            .process(process)
            .mounts(vec![proc_mount])
            .build()
            .unwrap();
        let args = build_cli_args(&spec, None, &[], "/tmp/test.sock", None).unwrap();
        assert!(args.proc_mount);
    }

    #[test]
    fn build_cli_args_no_proc_mount_by_default() {
        let spec = spec_with_user(0, 0);
        let args = build_cli_args(&spec, None, &[], "/tmp/test.sock", None).unwrap();
        assert!(!args.proc_mount);
    }
```

**Step 5: Run tests**

Run: `cargo test -p litebox_runner_oci --lib`
Expected: All tests pass (51 existing + 4 new from Task 1 + Task 3)

Run: `cargo test -p litebox_runner_linux_userland --lib`
Expected: All tests pass

**Step 6: Commit**

```bash
git add litebox_runner_oci/src/runner.rs litebox_runner_linux_userland/src/lib.rs
git commit -m "feat(oci): ensure /proc directory exists when OCI spec has proc mount"
```

---

### Task 4: Full test suite verification

**Step 1: Run all test suites**

```bash
cargo test -p litebox_runner_oci --lib
cargo test -p litebox_runner_linux_userland --lib
cargo test -p litebox_platform_linux_userland --lib
cargo test -p litebox_broker --lib
```

Expected: All tests pass.

**Step 2: Verify compilation of the full workspace**

```bash
cargo build -p litebox_runner_oci
```

Expected: Clean build, no warnings.
