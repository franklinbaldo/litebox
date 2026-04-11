# Fix Stdio Inherit + Eliminate posix_spawn Fallback

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the stdio `Inherit` binding (currently mapped to `/dev/null`, losing output) in all 4 spawn paths, then add bridge-pipe support to the forker paths so all binding types are handled without needing the posix_spawn fallback.

**Architecture:** Two sequential bugs. Bug A is a 1-line fix per match arm (4 arms total across 2 functions). Bug B requires creating OS pipe pairs for complex bindings (Fs/Pipe/Stream), sending child ends via SCM_RIGHTS to the forker, and spawning bridge threads in the parent — reusing the existing bridge infrastructure from the posix_spawn path.

**Tech Stack:** Rust, Unix (pipe/dup2/SCM_RIGHTS), litebox forker protocol

---

## Task 1: Fix `Inherit` binding in fork-restore forker path

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs:998-1003` (stdin) and `1021-1027` (stdout/stderr)

**Step 1: Fix stdin Inherit**

In `try_spawn_via_forker`, change the stdin catch-all from DevNull to handle Inherit explicitly:

```rust
// BEFORE (line 998-1003):
            _ => {
                stdio_bindings[0] = forker::StdioBinding::DevNull;
            }

// AFTER:
            WorkerExecInputBinding::Inherit => {
                stdio_bindings[0] = forker::StdioBinding::Inherit;
            }
            _ => {
                stdio_bindings[0] = forker::StdioBinding::DevNull;
            }
```

**Step 2: Fix stdout/stderr Inherit**

In the same function, change the stdout/stderr catch-all:

```rust
// BEFORE (line 1024-1026):
                _ => {
                    stdio_bindings[i] = forker::StdioBinding::DevNull;
                }

// AFTER:
                WorkerExecOutputBinding::Inherit => {
                    stdio_bindings[i] = forker::StdioBinding::Inherit;
                }
                _ => {
                    stdio_bindings[i] = forker::StdioBinding::DevNull;
                }
```

**Step 3: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All 21 tests pass.

**Step 4: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "fix(forker): map Inherit stdio binding to StdioBinding::Inherit in fork-restore path"
```

---

## Task 2: Fix `Inherit` binding in worker-exec forker path

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs:1257-1262` (stdin) and `1277-1282` (stdout/stderr)

**Step 1: Fix stdin Inherit**

In `try_spawn_worker_exec_via_forker`, change the stdin catch-all:

```rust
// BEFORE (line 1260-1262):
            _ => {
                stdio_bindings[0] = forker::StdioBinding::DevNull;
            }

// AFTER:
            WorkerExecInputBinding::Inherit => {
                stdio_bindings[0] = forker::StdioBinding::Inherit;
            }
            _ => {
                stdio_bindings[0] = forker::StdioBinding::DevNull;
            }
```

**Step 2: Fix stdout/stderr Inherit**

```rust
// BEFORE (line 1280-1282):
                _ => {
                    stdio_bindings[i] = forker::StdioBinding::DevNull;
                }

// AFTER:
                WorkerExecOutputBinding::Inherit => {
                    stdio_bindings[i] = forker::StdioBinding::Inherit;
                }
                _ => {
                    stdio_bindings[i] = forker::StdioBinding::DevNull;
                }
```

**Step 3: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All 21 tests pass.

**Step 4: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "fix(forker): map Inherit stdio binding to StdioBinding::Inherit in worker-exec path"
```

---

## Task 3: Fix `Inherit` binding in fork-restore posix_spawn path

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs:2378-2394` (stdin) and `2431-2448` (stdout/stderr)

**Step 1: Fix stdin Inherit**

In `spawn_worker_host_for_fork_restore`, add an explicit `Inherit` arm before the catch-all:

```rust
// BEFORE (line 2378-2394):
            // For Pipe/Stream/Fs/Inherit bindings, the mux handles all
            // actual data flow via virtual pipes.  Redirect the worker's
            // host stdin to /dev/null so it cannot read from the terminal.
            _ => {
                if unsafe {
                    libc::posix_spawn_file_actions_addopen(
                        file_actions_ptr,
                        0,
                        b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                        libc::O_RDONLY,
                        0,
                    )
                } != 0
                {
                    return Err(-1_i32);
                }
            }

// AFTER:
            WorkerExecInputBinding::Inherit => {
                // Let fd 0 pass through from the parent — no file action needed.
            }
            // For Pipe/Stream/Fs bindings, the mux handles all
            // actual data flow via virtual pipes.  Redirect the worker's
            // host stdin to /dev/null so it cannot read from the terminal.
            _ => {
                if unsafe {
                    libc::posix_spawn_file_actions_addopen(
                        file_actions_ptr,
                        0,
                        b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                        libc::O_RDONLY,
                        0,
                    )
                } != 0
                {
                    return Err(-1_i32);
                }
            }
```

**Step 2: Fix stdout/stderr Inherit**

```rust
// BEFORE (line 2431-2448):
                // For Pipe/Stream/Fs/Inherit bindings, the mux handles all
                // actual data flow via virtual pipes.  Redirect the worker's
                // host stdout/stderr to /dev/null so it cannot write to the
                // terminal.
                _ => {
                    if unsafe {
                        libc::posix_spawn_file_actions_addopen(
                            file_actions_ptr,
                            fd_num,
                            b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                            libc::O_WRONLY,
                            0,
                        )
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }

// AFTER:
                WorkerExecOutputBinding::Inherit => {
                    // Let fd pass through from the parent — no file action needed.
                }
                // For Pipe/Stream/Fs bindings, the mux handles all
                // actual data flow via virtual pipes.  Redirect the worker's
                // host stdout/stderr to /dev/null so it cannot write to the
                // terminal.
                _ => {
                    if unsafe {
                        libc::posix_spawn_file_actions_addopen(
                            file_actions_ptr,
                            fd_num,
                            b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
                            libc::O_WRONLY,
                            0,
                        )
                    } != 0
                    {
                        return Err(-1_i32);
                    }
                }
```

**Step 3: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All 21 tests pass.

**Step 4: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "fix(posix_spawn): map Inherit stdio binding to no-op in fork-restore path"
```

---

## Task 4: Add bridge-pipe support to fork-restore forker path (`try_spawn_via_forker`)

This is the core of Bug B for fork-restore. Currently, `Fs`/`Pipe`/`Stream` stdin bindings and `Fs`/`Pipe`/`Stream` stdout/stderr bindings are mapped to `DevNull` in the forker path. We need to:
1. Create OS pipe pairs for complex bindings
2. Send the child's end via SCM_RIGHTS (add to `fds_array`)
3. Map to `StdioBinding::FromFdIndex(idx)` 
4. After forker responds with PID, spawn bridge threads with the parent's end

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` — `try_spawn_via_forker` (~line 918) and `spawn_worker_host_for_fork_restore` (~line 2140)

**Step 1: Collect input source and output groups before the forker call**

In `try_spawn_via_forker`, after building the `fds_array` for simple bindings, add bridge pipe creation for complex bindings:

For stdin, replace the `_ => DevNull` catch-all (which after Task 1 will be for `Fs`/`Pipe`/`Stream` only):

```rust
            // Complex bindings: create a pipe, send child's read-end to forker,
            // parent keeps write-end for bridge thread.
            _ => {
                let (read_fd, write_fd) =
                    create_worker_stdio_pipe(false, false, None).map_err(|_| ())?;
                let idx = fds_array.len() as u8;
                fds_array.push(read_fd.as_raw_fd());
                keep_alive_fds.push(read_fd);
                stdio_bindings[0] = forker::StdioBinding::FromFdIndex(idx);
                stdin_bridge_write_fd = Some(write_fd);
            }
```

For stdout/stderr, same pattern but using `(write_fd, read_fd)` (child gets write end):

```rust
                _ => {
                    let (read_fd, write_fd) =
                        create_worker_stdio_pipe(false, false, None).map_err(|_| ())?;
                    let idx = fds_array.len() as u8;
                    fds_array.push(write_fd.as_raw_fd());
                    keep_alive_fds.push(write_fd);
                    stdio_bindings[i] = forker::StdioBinding::FromFdIndex(idx);
                    output_bridge_read_fds.push((i as libc::c_int, read_fd));
                }
```

**Step 2: After receiving PID from forker, spawn bridge threads**

After the `recv_fork_response` call succeeds:

```rust
        // Spawn bridge threads for complex stdio bindings.
        let mut bridge_threads = Vec::new();

        if let Some(write_fd) = stdin_bridge_write_fd {
            if let Some(input_source) = collect_worker_exec_input_source(&stdio) {
                let bridge = spawn_worker_input_bridge(self, input_source, write_fd)
                    .map_err(|_| ())?;
                bridge_threads.push(bridge);
            }
        }

        let output_groups = collect_worker_exec_output_groups(&stdio);
        for (target_fd, read_fd) in output_bridge_read_fds {
            // Find the matching output group for this target_fd.
            if let Some(group) = output_groups.iter().find(|g| g.target_fds.contains(&target_fd)) {
                let sink = match &group.sink {
                    WorkerExecOutputSink::Fs { fs, fd } => WorkerExecOutputSink::Fs {
                        fs: fs.clone(),
                        fd: fd.clone(),
                    },
                    WorkerExecOutputSink::Pipe { pipes, fd } => WorkerExecOutputSink::Pipe {
                        pipes: pipes.clone(),
                        fd: fd.clone(),
                    },
                    WorkerExecOutputSink::Stream(writer) => {
                        WorkerExecOutputSink::Stream(writer.clone())
                    }
                };
                let handle = spawn_worker_output_bridge(self, sink, read_fd)
                    .map_err(|_| ())?;
                bridge_threads.push(DetachedWorkerBridge {
                    handle,
                    input_control: None,
                });
            }
        }

        // Store bridge threads so they get joined on worker exit.
        if !bridge_threads.is_empty() {
            self.worker_processes.lock().unwrap()
                .entry(pid)
                .and_modify(|wp| wp.bridge_threads.extend(bridge_threads.drain(..)))
                .or_insert_with(|| WorkerHostProcess {
                    result_fd: result_read_fd,
                    bridge_threads,
                });
        }
```

**Note:** The function currently stores `result_read_fd` in `worker_processes` after a successful spawn. We need to ensure bridge threads are stored alongside it. Check the existing post-spawn code in `try_spawn_via_forker` (~line 1080-1115) and integrate bridge thread storage there.

**Step 3: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All tests pass. No functional change for simple bindings.

**Step 4: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat(forker): add bridge-pipe support for Fs/Pipe/Stream bindings in fork-restore path"
```

---

## Task 5: Add bridge-pipe support to worker-exec forker path (`try_spawn_worker_exec_via_forker`)

Same pattern as Task 4 but for `try_spawn_worker_exec_via_forker`. Additionally, support `direct_pipe_io` for Pipe bindings.

**Files:**
- Modify: `litebox_platform_linux_userland/src/lib.rs` — `try_spawn_worker_exec_via_forker` (~line 1147) and `spawn_worker_host_for_exec` (~line 1623)

**Step 1: Change `try_spawn_worker_exec_via_forker` signature**

Add `direct_pipe_io: bool` parameter (passed from `spawn_worker_host_for_exec`). Change return type from `Result<i32, ()>` to `Result<WorkerExecSpawnResult, ()>` so it can return `direct_pipes`.

**Step 2: Add bridge pipe creation for complex stdin binding**

Same pattern as Task 4 Step 1 for stdin.

**Step 3: Add bridge pipe creation for complex stdout/stderr bindings**

Same pattern, but also handle pipe capacity and nonblocking for Pipe bindings (matching the posix_spawn path logic at lines 1878-1896):

```rust
                WorkerExecOutputBinding::Pipe { pipes, fd } => {
                    let write_nonblocking = pipes
                        .get_flags(fd.as_ref())
                        .map(|flags| flags.contains(litebox::pipes::Flags::NON_BLOCKING))
                        .unwrap_or(false);
                    let write_capacity = pipes
                        .writable_bytes(fd.as_ref())
                        .ok()
                        .filter(|capacity| supports_bridge_pipe_capacity(*capacity));
                    if write_nonblocking && write_capacity.is_none() {
                        return Err(());
                    }
                    let (read_fd, write_fd) =
                        create_worker_stdio_pipe(false, write_nonblocking, write_capacity)
                            .map_err(|_| ())?;
                    let idx = fds_array.len() as u8;
                    fds_array.push(write_fd.as_raw_fd());
                    keep_alive_fds.push(write_fd);
                    stdio_bindings[i] = forker::StdioBinding::FromFdIndex(idx);
                    output_bridge_read_fds.push((i as libc::c_int, read_fd));
                }
```

**Step 4: After spawn, spawn bridge threads or return direct_pipes**

Same pattern as Task 4 Step 2, plus `direct_pipe_io` handling for Pipe bindings (matching posix_spawn path lines 1944-1984):

```rust
        // For input bridges:
        if direct_pipe_io && matches!(&source, WorkerExecInputSource::Pipe { .. }) {
            let raw_fd = write_fd.into_raw_fd();
            direct_pipes.push(ExecPipeDirectIo { child_stdio_fd: 0, parent_os_fd: raw_fd });
        } else {
            // spawn bridge thread
        }
```

**Step 5: Update `spawn_worker_host_for_exec` caller**

At line 1644, update the call to pass `direct_pipe_io` and handle the new `WorkerExecSpawnResult` return:

```rust
        if let Ok(result) = self.try_spawn_worker_exec_via_forker(
            guest_binary_path, argv, envp, guest_cwd,
            guest_pid, guest_ppid, guest_uid, guest_euid, guest_gid, guest_egid,
            guest_exec_image, guest_interp_image, &stdio, direct_pipe_io,
        ) {
            return Ok(result);
        }
```

**Step 6: Run tests**

Run: `cargo test -p litebox_platform_linux_userland -- forker`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs
git commit -m "feat(forker): add bridge-pipe and direct_pipe_io support for worker-exec path"
```

---

## Task 6: Integration test with Alpine tar

**Step 1: Run the Alpine stress test**

```bash
timeout 30 ./target/debug/litebox_runner_linux_userland -Z \
  --initial-files /tmp/alpine-test/alpine.tar \
  --program-from-tar --interception-backend rewriter \
  /bin/sh -c 'echo hello; result=$(echo world); echo "got: $result"; echo abc | while read line; do echo "piped: $line"; done'
```

Expected output includes:
```
hello
got: world
piped: abc
```

Previously `$(...)` returned empty and `| while read` hung. Both should now work.

**Step 2: Run the full stress test from before**

```bash
timeout 60 ./target/debug/litebox_runner_linux_userland -Z \
  --initial-files /tmp/alpine-test/alpine.tar \
  --program-from-tar --interception-backend rewriter \
  /bin/sh -c '
    echo "=== Pipeline ===" && echo hello | tr a-z A-Z | cat
    echo "=== Command sub ===" && result=$(echo "from subshell") && echo "got: $result"
    echo "=== While read ===" && printf "a\nb\nc\n" | while read line; do echo "line: $line"; done
    echo "=== Background ===" && echo bg1 & echo bg2 & wait
    echo DONE
  '
```

Expected: All sections produce correct output, no hangs.

**Step 3: Commit plan docs**

```bash
git add docs/plans/2026-04-11-stdio-inherit-and-eliminate-posix-spawn.md
git commit -m "docs: add implementation plan for stdio Inherit fix and posix_spawn elimination"
```

---

## Task 7: Polish — remove or feature-gate posix_spawn fallback code

Once Tasks 1-6 are verified, the posix_spawn paths in `spawn_worker_host_for_exec` (lines 1674-1997) and `spawn_worker_host_for_fork_restore` (lines 2232-2550) are dead code when the forker is available.

**Step 1: Add `#[cfg(feature = "posix_spawn_fallback")]` gate**

Wrap the posix_spawn fallback sections with a feature gate so they compile but are not used by default:

```rust
        // Fall through to posix_spawn path.
        #[cfg(feature = "posix_spawn_fallback")]
        {
            // ... existing posix_spawn code ...
        }
        #[cfg(not(feature = "posix_spawn_fallback"))]
        {
            return Err(-1_i32);
        }
```

**Step 2: Add feature to Cargo.toml**

In `litebox_platform_linux_userland/Cargo.toml`:

```toml
[features]
default = []
posix_spawn_fallback = []
```

**Step 3: Verify build without feature**

```bash
cargo build -p litebox_platform_linux_userland
cargo test -p litebox_platform_linux_userland -- forker
```

**Step 4: Verify build with feature**

```bash
cargo build -p litebox_platform_linux_userland --features posix_spawn_fallback
```

**Step 5: Run Alpine test (without feature = forker only)**

Same test as Task 6.

**Step 6: Commit**

```bash
git add litebox_platform_linux_userland/src/lib.rs litebox_platform_linux_userland/Cargo.toml
git commit -m "feat(forker): feature-gate posix_spawn fallback, forker handles all stdio binding types"
```
