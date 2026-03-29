# Child Orphaning Fix & Shebang Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the child orphaning bug (context1/fstime benchmarks timeout) and add shebang support (shell1/shell8 benchmarks fail), completing all non-graphics UnixBench benchmarks under micro-LiteBox.

**Architecture:** Two independent features: (1) Central's `ProcessServer` tracks child server thread `JoinHandle`s and joins them before `run()` returns, preventing premature central exit while children are still running. (2) Central's `handle_execve` detects `#!` shebang lines, parses the interpreter path, and re-dispatches the execve with the interpreter binary as the target.

**Tech Stack:** Rust, litebox_central server, Python benchmark runner

---

## Feature 1: Child Orphaning Fix

### Problem

When the parent process calls `exit_group`, central's server loop (`run()`) detects `primary_task.is_exiting()` and breaks. `main()` then returns, terminating the entire central OS process — including any child server threads spawned by `handle_fork()`. The child guest process's ring becomes unserviced, and it hangs forever on `submit_and_wait()` (futex_wait with no waker).

This affects **context1** (fork+pipe benchmark) and **fstime** (fork for read/write workload split).

### Root Cause Details

- `handle_fork()` at `server.rs:433` calls `std::thread::spawn()` and **drops** the `JoinHandle`.
- `run()` at `server.rs:165-167` breaks on `primary_task.is_exiting()`.
- `main()` at `main.rs:122` calls `server.run()` which returns `Ok(())`, then `main()` exits.
- OS process termination kills all threads, including child server threads.
- Child guest detects pipe EOF, tries syscalls, but its ring is dead.

### Design

Add a `child_handles: RefCell<Vec<JoinHandle<()>>>` field to `ProcessServer`. In `handle_fork()`, push the `JoinHandle` instead of dropping it. After the `run()` loop breaks, join all child handles before returning. This is safe because:

- `ProcessServer` is single-threaded (uses `RefCell`/`Cell`), so `child_handles` is only accessed from the owning thread.
- After the loop breaks, joining child handles blocks the parent server thread until all children exit, keeping the central process alive.
- Child processes will eventually exit (context1: pipe break → exit; fstime: alarm → exit).

### Task 1: Add child handle tracking to ProcessServer

**Files:**
- Modify: `litebox_central/src/server.rs:35-53` (struct definition)
- Modify: `litebox_central/src/server.rs:55-73` (constructor)

**Step 1: Add `child_handles` field to `ProcessServer` struct**

Add `use std::thread::JoinHandle;` to the imports and add a field:

```rust
pub struct ProcessServer<FS: ShimFS> {
    region: SharedRegion,
    primary_task: litebox_shim_linux::LinuxShimTask<FS>,
    thread_tasks: RefCell<HashMap<u16, litebox_shim_linux::LinuxShimTask<FS>>>,
    pending_tasks: RefCell<Vec<litebox_shim_linux::LinuxShimTask<FS>>>,
    next_thread_slot: Cell<u16>,
    next_child_pid: Cell<i32>,
    shim: Arc<litebox_shim_linux::LinuxShim<FS>>,
    fs: Arc<FS>,
    /// Join handles for child server threads spawned by `handle_fork`.
    /// Joined when this server's `run()` loop exits, preventing premature
    /// central process termination while children are still running.
    child_handles: RefCell<Vec<JoinHandle<()>>>,
}
```

**Step 2: Initialize the field in `new()`**

```rust
    pub fn new(/* ... */) -> Self {
        Self {
            // ... existing fields ...
            child_handles: RefCell::new(Vec::new()),
        }
    }
```

### Task 2: Store JoinHandle in handle_fork

**Files:**
- Modify: `litebox_central/src/server.rs:427-438` (handle_fork child spawn)

**Step 1: Replace the fire-and-forget spawn with handle tracking**

Change from:
```rust
        {
            let shim = self.shim.clone();
            let fs = self.fs.clone();
            let child_server = ProcessServer::new(child_region, child_task, shim, fs);
            child_server.next_child_pid.set(self.next_child_pid.get());

            std::thread::spawn(move || {
                if let Err(e) = child_server.run() {
                    eprintln!("litebox_central: child server error: {e}");
                }
            });
        }
```

To:
```rust
        {
            let shim = self.shim.clone();
            let fs = self.fs.clone();
            let child_server = ProcessServer::new(child_region, child_task, shim, fs);
            child_server.next_child_pid.set(self.next_child_pid.get());

            let handle = std::thread::spawn(move || {
                if let Err(e) = child_server.run() {
                    eprintln!("litebox_central: child server error: {e}");
                }
            });
            self.child_handles.borrow_mut().push(handle);
        }
```

### Task 3: Join child handles after run() loop exits

**Files:**
- Modify: `litebox_central/src/server.rs:163-171` (after loop break)

**Step 1: Join all child handles before returning from `run()`**

Change from:
```rust
            if self.primary_task.is_exiting() {
                break;
            }
        }

        Ok(())
    }
```

To:
```rust
            if self.primary_task.is_exiting() {
                break;
            }
        }

        // Wait for all child server threads to finish before returning.
        // This prevents the central process from exiting while children
        // are still processing syscalls (the OS would kill child threads,
        // leaving child guest processes hanging on dead rings).
        let handles: Vec<_> = self.child_handles.borrow_mut().drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }

        Ok(())
    }
```

### Task 4: Build and test

**Step 1: Build**

```bash
cargo build -p litebox_central 2>&1
```

Expected: Clean build.

**Step 2: Run existing tests**

```bash
cargo nextest run -p litebox_central -p litebox_micro -p litebox_ipc -p litebox_launcher
```

Expected: All pass, no regressions.

**Step 3: Run context1 benchmark**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks context1 --duration 5 --iterations 1
```

Expected: context1 passes (no timeout).

**Step 4: Run fstime benchmark**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks fstime --duration 5 --iterations 1
```

Expected: fstime passes (no timeout).

**Step 5: Regression check**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks dhry2reg pipe syscall spawn execl --duration 5 --iterations 1
```

Expected: All pass.

**Step 6: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "fix: wait for child server threads before central exits

Central's main thread now joins all child server JoinHandles after the
primary process exits, preventing premature process termination that
left child guest processes hanging on dead rings."
```

---

## Feature 2: Shebang Support

### Problem

When `looper` calls `execvp("multi.sh")`, central's `handle_execve` reads the file, tries `ElfParsedFile::parse()`, which fails because it starts with `#!` not `\x7fELF`, and returns `-ENOEXEC`.

### Design

Insert a shebang check in `handle_execve()` between the file read (line ~981) and the ELF parse (line ~984). If the file starts with `#!`, parse the first line for an interpreter path and optional argument, then recursively re-open and parse the interpreter as an ELF. Rebuild argv as `[interpreter, optional_arg, script_path, original_argv[1:]]`.

Linux shebang rules:
- Max 256 bytes in the first line (including `#!`)
- Interpreter path starts after `#!` (optional whitespace), ends at first whitespace or newline
- Optional single argument between interpreter and newline
- Script path becomes argv[1] (or argv[2] if there's an interpreter arg)
- Recursive shebangs are NOT supported (Linux limit: 1 level)

### Task 5: Add shebang detection and parsing to handle_execve

**Files:**
- Modify: `litebox_central/src/server.rs:981-988` (between file read and ELF parse)

**Step 1: Add shebang parsing helper function**

Add this function before `handle_execve` (or after the `MemReader` struct):

```rust
/// Parse a `#!` shebang line from the start of a file.
///
/// Returns `Some((interpreter_path, optional_arg))` if the file starts with
/// `#!`. The interpreter path and optional argument are byte slices without
/// leading/trailing whitespace. Returns `None` if the file is not a shebang
/// script.
///
/// Linux limits shebang parsing to the first 256 bytes.
fn parse_shebang(data: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if data.len() < 3 || data[0] != b'#' || data[1] != b'!' {
        return None;
    }

    // Find the end of the first line (max 256 bytes per Linux convention).
    let max_len = data.len().min(256);
    let line_end = data[2..max_len]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(max_len, |p| p + 2);
    let line = &data[2..line_end];

    // Skip leading whitespace after #!
    let line = &line[line.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(line.len())..];
    if line.is_empty() {
        return None;
    }

    // Interpreter path: up to first whitespace
    let interp_end = line
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let interp = &line[..interp_end];
    if interp.is_empty() {
        return None;
    }

    // Optional argument: rest of line, trimmed
    let rest = &line[interp_end..];
    let rest = &rest[rest.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(rest.len())..];
    let rest = &rest[..rest.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(0, |p| p + 1)];

    let arg = if rest.is_empty() { None } else { Some(rest) };
    Some((interp, arg))
}
```

**Step 2: Insert shebang handling in handle_execve between file close and ELF parse**

After `self.close_fd(thread_slot, fd);` (line 981) and before `let mut reader = MemReader(&file_data);` (line 984), add:

```rust
        // Check for shebang (#!) scripts.
        if let Some((interp_path, interp_arg)) = parse_shebang(&file_data) {
            // Re-open and load the interpreter binary instead.
            // Rebuild argv: [interpreter, optional_arg, script_path, original_argv[1:]]
            let script_path = path_bytes;

            // Build the new argv. Use the interpreter as argv[0], then
            // optional interpreter arg, then the script path, then the
            // original argv[1:].
            let mut new_argv: Vec<&[u8]> = Vec::new();
            new_argv.push(interp_path);
            if let Some(arg) = interp_arg {
                new_argv.push(arg);
            }
            new_argv.push(script_path);
            for a in argv_strs.iter().skip(1) {
                new_argv.push(a);
            }

            // Re-serialize and call handle_execve_inner with the interpreter path.
            return self.handle_execve_inner(
                entry, interp_path, &new_argv, &envp_strs, thread_slot,
            );
        }
```

### Task 6: Extract inner execve logic into handle_execve_inner

**Files:**
- Modify: `litebox_central/src/server.rs:885-` (refactor handle_execve)

The current `handle_execve` does deserialization + file open/read + ELF parse + segment packing. We need to extract the "file open/read + ELF parse + segment packing" part into `handle_execve_inner` so shebang can call it with a different path/argv.

**Step 1: Create `handle_execve_inner` method**

Extract everything from the file-open (`// Open the file via shim dispatch`) through the end of `handle_execve` into a new method:

```rust
    /// Inner execve handler: opens the target binary, parses ELF, packs segments.
    ///
    /// This is separated from `handle_execve` to allow shebang scripts to
    /// re-dispatch with the interpreter binary as the target.
    fn handle_execve_inner(
        &self,
        entry: &SqEntry,
        path_bytes: &[u8],
        argv_strs: &[&[u8]],
        envp_strs: &[&[u8]],
        thread_slot: u16,
    ) -> CqEntry {
        let mut cq = Self::base_cq(entry);

        // Build null-terminated path...
        // (rest of the existing open/read/parse/pack logic)
    }
```

**Step 2: Make `handle_execve` call `handle_execve_inner`**

```rust
    fn handle_execve(&self, entry: &SqEntry) -> CqEntry {
        // ... deserialization of path, argv, envp (unchanged) ...

        // Check for shebang after reading the file — but we need the file
        // content first. Since we need to read the file to detect shebang,
        // we do a lightweight "peek" approach:
        // 1. Open and read the file
        // 2. If shebang, re-open the interpreter
        // 3. If ELF, continue with existing logic
        //
        // Actually, the simplest approach: try ELF parse first, if ENOEXEC
        // then check for shebang. But that changes error semantics.
        //
        // Better: delegate to handle_execve_inner which handles both cases.
        self.handle_execve_inner(entry, path_bytes, &argv_strs, &envp_strs, entry.thread_slot)
    }
```

Wait — this means `handle_execve_inner` needs to do the file read AND the shebang check. Let me restructure:

**Revised design**: Keep `handle_execve` doing deserialization only, then call `handle_execve_inner`. The inner function does: open file → read → shebang check (if shebang, recurse with interpreter path) → ELF parse → pack segments.

```rust
    fn handle_execve(&self, entry: &SqEntry) -> CqEntry {
        let mut cq = Self::base_cq(entry);
        let thread_slot = entry.thread_slot;

        // Deserialize path/argv/envp from data region (unchanged)
        let data = self.region.data_region();
        // ... deserialization code ...

        self.handle_execve_inner(entry, path_bytes, &argv_strs, &envp_strs, thread_slot)
    }

    /// Inner execve: open file, check shebang, parse ELF, pack segments.
    fn handle_execve_inner(
        &self,
        entry: &SqEntry,
        path_bytes: &[u8],
        argv_strs: &[&[u8]],
        envp_strs: &[&[u8]],
        thread_slot: u16,
    ) -> CqEntry {
        let mut cq = Self::base_cq(entry);

        // Open the file (existing code)
        let mut path_cstr = vec![0u8; path_bytes.len() + 1];
        // ...

        // Read file (existing code)
        // ...

        // Close fd
        self.close_fd(thread_slot, fd);

        // ── Shebang check ──
        if let Some((interp_path, interp_arg)) = parse_shebang(&file_data) {
            let mut new_argv: Vec<&[u8]> = Vec::new();
            new_argv.push(interp_path);
            if let Some(arg) = interp_arg {
                new_argv.push(arg);
            }
            new_argv.push(path_bytes);
            for a in argv_strs.iter().skip(1) {
                new_argv.push(a);
            }
            // Recursive call — limited to 1 level (interpreter must be ELF)
            return self.handle_execve_inner(
                entry, interp_path, &new_argv, envp_strs, thread_slot,
            );
        }

        // ── ELF parse (existing code) ──
        let mut reader = MemReader(&file_data);
        // ...
    }
```

### Task 7: Implement the refactoring

**Files:**
- Modify: `litebox_central/src/server.rs`

This is the actual code change. The steps are:

**Step 1: Add `parse_shebang` function** (before `handle_execve` or in a helper section)

**Step 2: Rename existing `handle_execve` to `handle_execve_inner`** with the new signature

**Step 3: Create new `handle_execve` wrapper** that deserializes and delegates

**Step 4: Insert shebang check** in `handle_execve_inner` after file read, before ELF parse

### Task 8: Build and basic test

**Step 1: Build**

```bash
cargo build -p litebox_central 2>&1
```

Expected: Clean build.

**Step 2: Run existing tests**

```bash
cargo nextest run -p litebox_central -p litebox_micro -p litebox_ipc -p litebox_launcher
```

Expected: All pass.

**Step 3: Run execl benchmark (regression check)**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks execl --duration 5 --iterations 1
```

Expected: Still passes (~1069 lps).

**Step 4: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat: add shebang (#!) support to central execve handler

When handle_execve reads a file starting with '#!', it parses the
interpreter path and optional argument from the first line, rebuilds
argv per Linux convention, and re-dispatches with the interpreter
binary as the target. Limited to one level of indirection."
```

---

## Feature 3: Shell Benchmark Packaging

### Problem

Shell benchmarks (`shell1`/`shell8`) need `/bin/sh`, `sort`, `od`, `grep`, `tee`, `wc`, `rm` (and their shared library dependencies) present in the rootfs tar as rewritten ELF binaries. Shell scripts (`multi.sh`, `tst.sh`) and data files (`sort.src`) must also be present but pass through unmodified.

### Design

Extend `prepare_micro_rootfs()` in `run_unixbench.py` to:
1. For shell benchmarks, run the packager on each required system binary
2. Add shell scripts and data files to the tar
3. Set `UB_BINDIR=/pgms` environment variable (already done for execl, extend to shell)

### Task 9: Add shell binary packaging to run_unixbench.py

**Files:**
- Modify: `dev_bench/unixbench/run_unixbench.py:473-538` (prepare_micro_rootfs)
- Modify: `dev_bench/unixbench/run_unixbench.py:575-579` (UB_BINDIR env)

**Step 1: Add SHELL_UTILITIES constant and helper function**

After the imports section, add:

```python
# System utilities required by shell benchmarks (multi.sh, tst.sh).
SHELL_UTILITIES = ["sort", "od", "grep", "tee", "wc", "rm", "cat"]
```

**Step 2: Add `add_shell_support_to_tar` function**

```python
def add_shell_support_to_tar(
    tar_path: Path,
    pgms_dir: Path,
    packager_path: Optional[Path],
    work_dir: Path,
) -> bool:
    """
    Add shell scripts, data files, and rewritten system utilities to the
    rootfs tar for shell benchmarks (shell1/shell8).

    Returns True on success, False on failure.
    """
    import tarfile as _tarfile
    import shutil

    # 1. Find /bin/sh (resolve symlink to actual binary, e.g. dash/bash)
    sh_path = shutil.which("sh")
    if sh_path is None:
        print("  Error: /bin/sh not found")
        return False
    sh_real = Path(sh_path).resolve()

    # 2. Collect all binaries to rewrite
    bins_to_rewrite = [sh_real]
    for util in SHELL_UTILITIES:
        util_path = shutil.which(util)
        if util_path is None:
            print(f"  Error: {util} not found in PATH")
            return False
        bins_to_rewrite.append(Path(util_path).resolve())

    # Deduplicate (e.g. if sh and bash are the same)
    bins_to_rewrite = list(dict.fromkeys(bins_to_rewrite))

    # 3. Rewrite each binary with the packager and collect the tar outputs
    rewritten_tars = []
    for binary in bins_to_rewrite:
        bin_tar = work_dir / f"rootfs_{binary.name}.tar"
        if packager_path:
            cmd = [str(packager_path)]
        else:
            cmd = ["cargo", "run", "-p", "litebox_packager", "--"]
        cmd += [str(binary), "-o", str(bin_tar)]
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            print(f"  Error: packager failed for {binary.name}: {stderr[:500]}")
            return False
        rewritten_tars.append(bin_tar)

    # 4. Merge all rewritten binaries into the main tar.
    # Also add /bin/sh symlink if the real shell is elsewhere (e.g. /usr/bin/dash).
    rebuilt_path = tar_path.with_suffix(".shell.tar")
    with _tarfile.open(rebuilt_path, "w", format=_tarfile.GNU_FORMAT) as out_tf:
        # Copy existing entries from the main tar
        with _tarfile.open(tar_path) as in_tf:
            for member in in_tf.getmembers():
                fileobj = in_tf.extractfile(member)
                out_tf.addfile(member, fileobj)

        # Merge entries from each utility's tar
        seen = set()
        for util_tar in rewritten_tars:
            with _tarfile.open(util_tar) as in_tf:
                for member in in_tf.getmembers():
                    if member.name not in seen:
                        seen.add(member.name)
                        fileobj = in_tf.extractfile(member)
                        out_tf.addfile(member, fileobj)

        # Add /bin/sh as a copy of the rewritten shell binary.
        # Find the rewritten shell in the utility tars.
        sh_in_tar = str(sh_real).lstrip("/")
        # Also ensure bin/sh exists for #! /bin/sh resolution
        sh_tar = rewritten_tars[0]  # first is always the shell
        with _tarfile.open(sh_tar) as in_tf:
            for member in in_tf.getmembers():
                if member.name == sh_in_tar:
                    fileobj = in_tf.extractfile(member)
                    data = fileobj.read()
                    # Add as bin/sh
                    sh_member = _tarfile.TarInfo(name="bin/sh")
                    sh_member.size = len(data)
                    sh_member.mode = 0o755
                    import io
                    out_tf.addfile(sh_member, io.BytesIO(data))
                    break

        # Add shell scripts from pgms/
        for script in ("multi.sh", "tst.sh"):
            script_path = pgms_dir / script
            if script_path.exists():
                out_tf.add(str(script_path), arcname=f"pgms/{script}")

        # Add sort.src data file
        sort_src = pgms_dir / "sort.src"
        if sort_src.exists():
            out_tf.add(str(sort_src), arcname="pgms/sort.src")

    rebuilt_path.rename(tar_path)
    return True
```

**Step 3: Call `add_shell_support_to_tar` from `prepare_micro_rootfs`**

After the execl block (line 537), add:

```python
    # For shell benchmarks: add /bin/sh, system utilities, scripts, and data
    if bench.name in ("shell1", "shell8"):
        if not add_shell_support_to_tar(tar_path, pgms_dir, packager_path, work_dir):
            return None
        # Re-extract (the tar changed)
        import tarfile as _tarfile
        with _tarfile.open(tar_path) as tf:
            tf.extractall(str(extract_dir))
```

**Step 4: Extend UB_BINDIR env to shell benchmarks**

Change the env setup in `run_micro()` from:
```python
    if bench.name == "execl":
        env["UB_BINDIR"] = "/pgms"
```

To:
```python
    if bench.name in ("execl", "shell1", "shell8"):
        env["UB_BINDIR"] = "/pgms"
```

### Task 10: Test shell benchmarks

**Step 1: Run shell1 benchmark**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks shell1 --duration 5 --iterations 1
```

Expected: shell1 passes.

**Step 2: Run shell8 benchmark**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --benchmarks shell8 --duration 5 --iterations 1
```

Expected: shell8 passes.

**Step 3: Commit**

```bash
git add dev_bench/unixbench/run_unixbench.py
git commit -m "feat: add shell benchmark support to micro-LiteBox runner

Extends prepare_micro_rootfs to package /bin/sh, system utilities
(sort, od, grep, tee, wc, rm, cat), shell scripts (multi.sh, tst.sh),
and data files (sort.src) for shell1/shell8 benchmarks."
```

---

## Task 11: Full regression test

**Step 1: Run all benchmarks**

```bash
cd /workspace/litebox-mu/dev_bench/unixbench
python3 run_unixbench.py --mode micro --duration 5 --iterations 1
```

Expected: All benchmarks pass (dhry2reg, whetstone-double, pipe, syscall, spawn, execl, context1, fstime, shell1, shell8).

---

## Task Summary

| Task | Feature | What |
|------|---------|------|
| 1 | Child orphaning | Add `child_handles` field to `ProcessServer` |
| 2 | Child orphaning | Store `JoinHandle` in `handle_fork` |
| 3 | Child orphaning | Join child handles after `run()` loop exits |
| 4 | Child orphaning | Build, test, verify context1/fstime, commit |
| 5-6 | Shebang | Add `parse_shebang` + design `handle_execve_inner` split |
| 7 | Shebang | Implement the refactoring |
| 8 | Shebang | Build, test, verify execl regression, commit |
| 9 | Shell packaging | Extend `run_unixbench.py` with shell utilities |
| 10 | Shell packaging | Test shell1/shell8, commit |
| 11 | All | Full regression test |
