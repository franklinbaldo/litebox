# Store argv/envp/program metadata in trace Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Store program path, argv, envp, and filesystem flags (`--initial-files`, `--program-from-tar`) in the RR trace so that replay uses the recorded values instead of CLI arguments. Different CLI arguments during replay won't cause divergence — they're simply ignored.

**Architecture:** Extend the trace header with a variable-length metadata section. The `TraceHeader` gains a `metadata: TraceMetadata` field containing all the info needed to reproduce the exact execution environment. The `Recorder` accepts metadata at construction time and serializes it after the fixed header. The `Replayer` parses it and exposes it. The runner reads metadata from the replayer during replay and uses it in place of CLI args. Trace format version bumps to 3; v2 traces are still readable (no metadata → fall back to CLI args with a warning).

**Tech Stack:** Rust, `no_std` with `alloc` (litebox_rr crate), `std` (runner crate)

---

### Task 1: Add `TraceMetadata` struct and serialization to `litebox_rr`

**Files:**
- Modify: `litebox_rr/src/trace.rs`

**Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `trace.rs`:

```rust
#[test]
fn test_metadata_roundtrip() {
    let meta = TraceMetadata {
        program_path: "/bin/ls".into(),
        argv: alloc::vec![ "/bin/ls".into(), "/usr".into() ],
        envp: alloc::vec![ "HOME=/".into(), "PATH=/bin".into() ],
        initial_files_path: Some("/tmp/rootfs.tar".into()),
        program_from_tar: false,
    };
    let bytes = meta.to_bytes();
    let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded, meta);
}

#[test]
fn test_metadata_empty_roundtrip() {
    let meta = TraceMetadata {
        program_path: "/hello".into(),
        argv: alloc::vec![ "/hello".into() ],
        envp: alloc::vec![],
        initial_files_path: None,
        program_from_tar: false,
    };
    let bytes = meta.to_bytes();
    let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded, meta);
}

#[test]
fn test_metadata_program_from_tar() {
    let meta = TraceMetadata {
        program_path: "/bin/ls".into(),
        argv: alloc::vec![ "/bin/ls".into() ],
        envp: alloc::vec![ "HOME=/".into() ],
        initial_files_path: Some("alpine.tar".into()),
        program_from_tar: true,
    };
    let bytes = meta.to_bytes();
    let (decoded, consumed) = TraceMetadata::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded, meta);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p litebox_rr`
Expected: FAIL — `TraceMetadata` not defined

**Step 3: Implement `TraceMetadata`**

Add to `trace.rs`, before `TraceHeader`:

```rust
use alloc::string::String;

/// Execution metadata stored in the trace header.
///
/// Contains everything needed to reconstruct the exact execution environment
/// during replay: program path, argv, envp, and filesystem flags.
///
/// Wire format:
/// ```text
/// u32 LE  total_len        (byte count of everything after this u32)
/// u32 LE  program_path_len
/// [u8]    program_path     (UTF-8)
/// u32 LE  argc
/// for each arg:
///   u32 LE  arg_len
///   [u8]    arg              (UTF-8)
/// u32 LE  envc
/// for each env:
///   u32 LE  env_len
///   [u8]    env              (UTF-8)
/// u8      flags             (bit 0 = program_from_tar, bit 1 = has_initial_files)
/// if has_initial_files:
///   u32 LE  initial_files_path_len
///   [u8]    initial_files_path (UTF-8)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct TraceMetadata {
    /// Path to the program binary (host path or guest path for program-from-tar).
    pub program_path: String,
    /// Command-line arguments (argv[0] is typically the program name).
    pub argv: Vec<String>,
    /// Environment variables (`KEY=VALUE` pairs).
    pub envp: Vec<String>,
    /// Path to the tar file with initial filesystem contents, if any.
    pub initial_files_path: Option<String>,
    /// Whether the program was loaded from the tar file.
    pub program_from_tar: bool,
}
```

Add serialization methods:

```rust
impl TraceMetadata {
    fn write_str(buf: &mut Vec<u8>, s: &str) {
        let len = s.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(s.as_bytes());
    }

    fn read_str(data: &[u8], offset: &mut usize) -> Result<String, TraceError> {
        if *offset + 4 > data.len() {
            return Err(TraceError::UnexpectedEof);
        }
        let len = u32::from_le_bytes(data[*offset..*offset + 4].try_into().unwrap()) as usize;
        *offset += 4;
        if *offset + len > data.len() {
            return Err(TraceError::UnexpectedEof);
        }
        let s = core::str::from_utf8(&data[*offset..*offset + len])
            .map_err(|_| TraceError::InvalidMetadata)?;
        *offset += len;
        Ok(s.into())
    }

    /// Serialize metadata to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        Self::write_str(&mut payload, &self.program_path);

        // argv
        let argc = self.argv.len() as u32;
        payload.extend_from_slice(&argc.to_le_bytes());
        for arg in &self.argv {
            Self::write_str(&mut payload, arg);
        }

        // envp
        let envc = self.envp.len() as u32;
        payload.extend_from_slice(&envc.to_le_bytes());
        for env in &self.envp {
            Self::write_str(&mut payload, env);
        }

        // flags
        let has_initial_files = self.initial_files_path.is_some();
        let flags: u8 = u8::from(self.program_from_tar) | (u8::from(has_initial_files) << 1);
        payload.push(flags);

        if let Some(ref path) = self.initial_files_path {
            Self::write_str(&mut payload, path);
        }

        // Prepend total_len
        let mut buf = Vec::with_capacity(4 + payload.len());
        let total_len = payload.len() as u32;
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.extend_from_slice(&payload);
        buf
    }

    /// Deserialize metadata from bytes, returning (metadata, bytes_consumed).
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), TraceError> {
        if data.len() < 4 {
            return Err(TraceError::UnexpectedEof);
        }
        let total_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        if data.len() < 4 + total_len {
            return Err(TraceError::UnexpectedEof);
        }

        let mut offset = 4;

        let program_path = Self::read_str(data, &mut offset)?;

        // argv
        if offset + 4 > data.len() {
            return Err(TraceError::UnexpectedEof);
        }
        let argc = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut argv = Vec::with_capacity(argc);
        for _ in 0..argc {
            argv.push(Self::read_str(data, &mut offset)?);
        }

        // envp
        if offset + 4 > data.len() {
            return Err(TraceError::UnexpectedEof);
        }
        let envc = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut envp = Vec::with_capacity(envc);
        for _ in 0..envc {
            envp.push(Self::read_str(data, &mut offset)?);
        }

        // flags
        if offset >= data.len() {
            return Err(TraceError::UnexpectedEof);
        }
        let flags = data[offset];
        offset += 1;
        let program_from_tar = flags & 1 != 0;
        let has_initial_files = flags & 2 != 0;

        let initial_files_path = if has_initial_files {
            Some(Self::read_str(data, &mut offset)?)
        } else {
            None
        };

        Ok((
            Self {
                program_path,
                argv,
                envp,
                initial_files_path,
                program_from_tar,
            },
            offset,
        ))
    }
}
```

Also add `InvalidMetadata` variant to `TraceError`:
```rust
pub enum TraceError {
    // ... existing variants ...
    /// Invalid metadata (e.g. non-UTF-8 string).
    InvalidMetadata,
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p litebox_rr`
Expected: PASS

**Step 5: Commit**

```
feat(litebox_rr): add TraceMetadata struct with serialization
```

---

### Task 2: Integrate metadata into `TraceHeader`, bump to v3

**Files:**
- Modify: `litebox_rr/src/trace.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn test_header_v3_with_metadata_roundtrip() {
    let meta = TraceMetadata {
        program_path: "/bin/ls".into(),
        argv: alloc::vec!["/bin/ls".into(), "-la".into()],
        envp: alloc::vec!["HOME=/".into()],
        initial_files_path: Some("rootfs.tar".into()),
        program_from_tar: true,
    };
    let header = TraceHeader {
        magic: TRACE_MAGIC,
        version: TRACE_VERSION,
        arch: TraceArch::X86_64,
        metadata: Some(meta.clone()),
    };
    let bytes = header.to_bytes();
    let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded.version, 3);
    assert_eq!(decoded.metadata, Some(meta));
}

#[test]
fn test_header_v2_no_metadata() {
    // Build a v2 header manually (9 bytes, no metadata).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TRACE_MAGIC);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.push(TraceArch::X86_64 as u8);
    let (decoded, consumed) = TraceHeader::from_bytes(&bytes).unwrap();
    assert_eq!(consumed, 9);
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.metadata, None);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p litebox_rr`
Expected: FAIL — `TraceHeader` doesn't have `metadata` field

**Step 3: Implement**

Update `TRACE_VERSION` to 3.

Add `metadata: Option<TraceMetadata>` field to `TraceHeader`.

Update `TraceHeader::to_bytes()`:
- For v3: write the 9-byte fixed header, then `metadata.to_bytes()`
- `TRACE_HEADER_SIZE` becomes a minimum; actual size depends on metadata

Update `TraceHeader::from_bytes()`:
- Accept versions 1, 2, and 3
- For v1/v2: `metadata = None`, consumed = 9
- For v3: parse metadata after the 9-byte fixed header

Update all existing tests that construct `TraceHeader` to include `metadata: None`.

Update `Recorder::new()` signature — see Task 3.

**Step 4: Run all tests in litebox_rr**

Run: `cargo test -p litebox_rr`
Expected: PASS (including existing tests updated for new field)

**Step 5: Commit**

```
feat(litebox_rr): add metadata to TraceHeader, bump to v3
```

---

### Task 3: Thread metadata through `Recorder` and `Replayer`

**Files:**
- Modify: `litebox_rr/src/recorder.rs`
- Modify: `litebox_rr/src/replayer.rs`
- Modify: `litebox_rr/src/lib.rs` (re-exports)

**Step 1: Write the failing test**

Add to `recorder.rs` tests:
```rust
#[test]
fn test_recorder_with_metadata() {
    let meta = TraceMetadata {
        program_path: "/bin/hello".into(),
        argv: alloc::vec!["/bin/hello".into()],
        envp: alloc::vec!["HOME=/".into()],
        initial_files_path: None,
        program_from_tar: false,
    };
    let mut recorder = Recorder::new(TraceArch::X86_64, Some(meta.clone()));
    recorder.record_simple(1, 0, alloc::vec![]);
    let trace = recorder.finish();

    let replayer = Replayer::from_bytes(trace).unwrap();
    assert_eq!(replayer.metadata(), Some(&meta));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p litebox_rr`
Expected: FAIL — `Recorder::new` takes wrong args

**Step 3: Implement**

- `Recorder::new(arch, metadata: Option<TraceMetadata>)` — constructs header with metadata, serializes to buffer
- `Replayer::from_bytes()` — already parses the header; store `metadata` from parsed header
- `Replayer::metadata(&self) -> Option<&TraceMetadata>` — getter

Update all existing `Recorder::new(arch)` call sites to pass `None` for metadata (tests in recorder.rs).

**Step 4: Run tests**

Run: `cargo test -p litebox_rr`
Expected: PASS

**Step 5: Commit**

```
feat(litebox_rr): thread TraceMetadata through Recorder and Replayer
```

---

### Task 4: Pass metadata from runner to `RRState` during recording

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` — `RRState::new()` accepts metadata
- Modify: `litebox_shim_linux/src/lib.rs` — `LinuxShimBuilder` gains metadata setter, plumbs to `RRState`
- Modify: `litebox_runner_linux_userland/src/lib.rs` — constructs `TraceMetadata` from CLI args and passes to builder

**Step 1: Update `RRState::new()` to accept metadata**

In `rr.rs`, change `RRState::new(mode: RRMode)` to `RRState::new(mode: RRMode, metadata: Option<TraceMetadata>)`:
- `RRMode::Record` → pass metadata to `Recorder::new(current_arch(), metadata)`
- `RRMode::Off` → ignore metadata

**Step 2: Add `set_rr_metadata()` to `LinuxShimBuilder`**

In `lib.rs`:
```rust
#[cfg(feature = "rr")]
pub fn set_rr_metadata(&mut self, metadata: litebox_rr::TraceMetadata) {
    self.rr_metadata = Some(metadata);
}
```

Add `rr_metadata: Option<litebox_rr::TraceMetadata>` field to builder struct, plumb through `build()`.

**Step 3: Construct metadata in runner**

In `litebox_runner_linux_userland/src/lib.rs`, in the `run()` function, after determining `prog_path` and before calling `shim_builder.set_rr_record()`:

```rust
if cli_args.rr_record.is_some() {
    let metadata = litebox_rr::TraceMetadata {
        program_path: prog_path.to_string(),
        argv: cli_args.program_and_arguments.clone(),
        envp: /* the final envp strings */,
        initial_files_path: cli_args.initial_files.as_ref().map(|p| p.display().to_string()),
        program_from_tar: cli_args.program_from_tar,
    };
    shim_builder.set_rr_metadata(metadata);
    shim_builder.set_rr_record();
}
```

Note: envp must include the computed environment variables (including `--forward-env` expansion), not just the CLI `--env` values. Capture envp after the `forward_environment_variables` logic.

**Step 4: Verify recording produces v3 traces**

Run: `cargo test -p litebox_runner_linux_userland --features rr test_rr_record_replay_hello`
Expected: PASS (recording produces v3 trace, replay reads v3 trace)

**Step 5: Commit**

```
feat: pass execution metadata into trace during recording
```

---

### Task 5: Use metadata from trace during replay (ignore CLI args)

**Files:**
- Modify: `litebox_shim_linux/src/rr.rs` — `RRState::new_replay()` exposes metadata
- Modify: `litebox_shim_linux/src/lib.rs` — `LinuxShimBuilder` exposes replay metadata
- Modify: `litebox_runner_linux_userland/src/lib.rs` — during replay, read metadata from trace and use it for program_path, argv, envp, initial_files, program_from_tar

**Step 1: Expose metadata from `RRState` and `LinuxShimBuilder`**

In `rr.rs`:
```rust
pub fn replay_metadata(&self) -> Option<&TraceMetadata> {
    self.replayer.as_ref()
        .and_then(|r| r.lock().metadata().cloned())
        // or store separately for lifetime reasons
}
```

Actually, since `Replayer` is behind a `Mutex`, it's easier to extract metadata at construction time and store it separately in `RRState`:

```rust
pub struct RRState {
    // ... existing fields ...
    /// Metadata from the trace (replay mode) or to be recorded (record mode).
    metadata: Option<TraceMetadata>,
}
```

In `LinuxShimBuilder`, after `set_rr_replay()` constructs the `Replayer`, extract metadata before building:
- Add `pub fn rr_replay_metadata(&self) -> Option<&TraceMetadata>` to the builder or the shim

Actually, the cleanest approach: `set_rr_replay()` parses the trace data into a `Replayer`, extracts metadata, and stores it. Then a getter returns it so the runner can use it before calling `build()`.

Alternative simpler approach: Parse the trace header in the runner itself (just the header, not the full replayer) to extract metadata before constructing the shim. This avoids modifying the shim API:

```rust
// In runner, before build():
if let Some(ref trace_path) = cli_args.rr_replay {
    let trace_data = std::fs::read(trace_path)?;
    let (header, _) = litebox_rr::TraceHeader::from_bytes(&trace_data)?;
    if let Some(meta) = &header.metadata {
        // Override CLI args with trace metadata
        prog_path = meta.program_path.clone();
        // ... etc
    }
    shim_builder.set_rr_replay(trace_data);
}
```

Use this simpler approach. The runner parses the header early to extract metadata, then uses it.

**Step 2: Restructure the runner's `run()` function for replay**

The key change: when `--rr-replay` is set, parse the trace header first to get metadata. Then use metadata values for:
- `program_and_arguments` → `meta.argv` (override the CLI values)  
- `environment_variables` / `forward_environment_variables` → `meta.envp` (override)
- `initial_files` → `meta.initial_files_path` (override)
- `program_from_tar` → `meta.program_from_tar` (override)
- Program binary path → `meta.program_path` (override)

For v2 traces (no metadata): fall back to CLI args with an `eprintln!` warning.

**Step 3: Verify with existing tests**

Run: `cargo nextest run -p litebox_runner_linux_userland --features rr`
Expected: All RR tests PASS

**Step 4: Commit**

```
feat: use recorded metadata during replay, ignore CLI args
```

---

### Task 6: Write integration test for argv independence

**Files:**
- Modify: `litebox_runner_linux_userland/tests/run.rs`

**Step 1: Write the test**

```rust
/// Record with one set of args, replay with different args on the CLI.
/// The replay should succeed because it uses the trace's stored argv, not the CLI's.
#[cfg(feature = "rr")]
#[test]
fn test_rr_replay_ignores_cli_args() {
    let unique_name = "replay_argv_rr";
    let target = common::compile("./tests/hello.c", unique_name, true, false);
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let trace_path = dir.join("replay_argv_rr.trace");

    // --- Record ---
    Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_record"))
        .runner_arg("--rr-record")
        .runner_arg(&trace_path)
        .run();

    assert!(trace_path.exists(), "trace file was not created");

    // --- Replay with DIFFERENT CLI program path + args ---
    // The runner should ignore the CLI args and use the trace metadata.
    // We pass a dummy program path that differs from the recorded one,
    // but since replay reads metadata from the trace, it should still work.
    // Note: We still need to pass *something* for program_and_arguments
    // since clap requires it, but the value is ignored during replay.
    Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_replay"))
        .runner_arg("--rr-replay")
        .runner_arg(&trace_path)
        .run();
}
```

Wait — this doesn't actually test that different args are ignored, because the test helper always constructs the same binary path. Let me think about this more carefully...

The real test is: record `hello arg1 arg2`, replay with `hello different_arg`. The output (via `--rr-replay-stdout`) should show `arg1 arg2` (from trace) not `different_arg`.

```rust
/// Record hello.c with specific args, replay with different CLI args.
/// Verify that replay output matches the recording (trace argv is used).
#[cfg(feature = "rr")]
#[test]
fn test_rr_replay_uses_trace_argv() {
    let unique_name = "trace_argv_rr";
    let target = common::compile("./tests/hello.c", unique_name, true, false);
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let trace_path = dir.join("trace_argv_rr.trace");

    // --- Record with specific args ---
    let record_output = Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_record"))
        .runner_arg("--rr-record")
        .runner_arg(&trace_path)
        .arg("recorded_arg")
        .output();

    let record_str = String::from_utf8_lossy(&record_output);
    assert!(record_str.contains("recorded_arg"), "recording should show recorded_arg");

    // --- Replay with different CLI args but --rr-replay-stdout ---
    // The CLI args are ignored; trace metadata argv is used instead.
    let replay_output = Runner::new(Backend::Rewriter, &target, &format!("{unique_name}_replay"))
        .runner_arg("--rr-replay")
        .runner_arg(&trace_path)
        .runner_arg("--rr-replay-stdout")
        .arg("WRONG_ARG_SHOULD_BE_IGNORED")
        .output();

    let replay_str = String::from_utf8_lossy(&replay_output);
    // Replay should show the recorded args, not the CLI args
    assert_eq!(
        record_output, replay_output,
        "replay should use trace argv, not CLI argv\n--- record ---\n{record_str}\n--- replay ---\n{replay_str}"
    );
}
```

**Step 2: Run test to verify it fails (before Task 5 implementation)**

Actually this test validates Task 5's implementation. Run it after Task 5 is done.

Run: `cargo nextest run -p litebox_runner_linux_userland --features rr test_rr_replay_uses_trace_argv`
Expected: PASS

**Step 3: Run the full test suite**

Run: `cargo nextest run --features rr --no-fail-fast`
Expected: Same pre-existing failures only (18 failures: 15 tun, 2 tun_nine_p, 1 node)

**Step 4: Commit**

```
test: add integration test verifying replay uses trace argv
```

---

### Task 7: Final cleanup and full verification

**Files:**
- All modified files

**Step 1: cargo fmt**

Run: `cargo fmt`

**Step 2: cargo clippy**

Run: `cargo clippy --all-targets --features rr`
Expected: No new warnings

**Step 3: Full test suite**

Run: `cargo nextest run --features rr --no-fail-fast`
Expected: 235+ passed (234 previous + new test), 18 pre-existing failures

**Step 4: Commit all remaining changes**

If any formatting/clippy fixes were needed, commit them.
