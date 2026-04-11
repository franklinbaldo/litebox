# OCI Runner with Fork Support — Design

## Problem

The old `litebox_runner_oci` (on the `oci` branch) was a fully functional OCI-compliant
container runtime, but it lacked fork() support. This forced 4 layers of workarounds:

1. **litebox-sh**: A custom fork-free shell binary (~435KB, statically linked, embedded via
   `include_bytes!`)
2. **Shell rewriting**: `sh -c "..."` → `litebox-sh -c "..."`
3. **Shebang rewriting**: `#!/bin/sh` → `#!/bin/litebox-sh` in rootfs files
4. **Pipeline orchestration**: `cmd1 | cmd2` run as separate LiteBox processes via re-exec

The current branch (`sanghle/agent-sandbox-fork`) has implemented:
- A forker process that creates workers via `fork()` (no `execve` on the hot path)
- Host-level seccomp sandbox on the forker (35-syscall allowlist)
- Listening socket fork-restore for multi-process networking

Real shells now work. All workarounds are unnecessary.

## Solution

Port the old OCI runner into this repo as a new `litebox_runner_oci` crate. The key insight
is that the OCI runner is a **thin CLI adapter** — it translates OCI bundle semantics into
`CliArgs` and delegates to `litebox_runner_linux_userland::run()`.

## Architecture

```
containerd / podman / ctr / crictl
        |
        v
litebox-oci (OCI CLI binary)
  main.rs    — clap CLI: create/start/state/kill/delete/run/exec/list/events
  lifecycle.rs — OCI lifecycle state machine (fork + Unix socket sync)
  state.rs   — on-disk state persistence (state.json per container)
  runner.rs  — OCI bundle → spawn broker → build CliArgs → run()
        |
        v
litebox_broker (child process, spawned by runner.rs)
  --network-proxy-listen <socket> — smoltcp network proxy
  --root-dir <rootfs>             — 9P file server for host FS access
  --rewrite-syscalls              — patch ELFs on the fly
  --read-only --writable-path /tmp — policy enforcement
        |
        v
litebox_runner_linux_userland::run(cli_args)
  -- platform init, forker spawn, seccomp, 9P connection, shim build
  -- program loading, guest execution
```

### Key Design Decisions

1. **9P broker for rootfs** — Instead of walking the rootfs directory and copying files into
   an in-memory FS (the old approach), the OCI runner spawns a `litebox_broker` process that
   serves the rootfs via 9P2000.L over shared-memory ring buffers. Files are loaded lazily on
   demand. The broker rewrites ELF syscall instructions on the fly (`--rewrite-syscalls`).

2. **Thin wrapper over existing runner** — The OCI runner constructs a `CliArgs` struct and
   calls `litebox_runner_linux_userland::run()`. This reuses 100% of the existing init logic:
   forker spawn, platform creation, seccomp, shim building, FS composition, program loading.

3. **Full OCI lifecycle** — The lifecycle module (create/start/state/kill/delete) is ported
   from the old runner. It uses fork + Unix socket synchronization for the create/start split
   required by the OCI spec.

4. **Full CNI networking** — Auto-detects CNI network namespaces from the OCI spec, enters
   them, creates a TUN device, and sets up NAT. The runner connects to the broker's network
   proxy via `--network-broker` for smoltcp-based TCP/UDP/ICMP.

5. **No fork workarounds** — All 4 workaround layers are removed. Real shells (bash, dash,
   ash) fork+exec normally. Pipes, subshells, background jobs all work.

### Runner Flow (run command)

1. Parse `config.json` from OCI bundle → extract process args, env, cwd, rootfs path
2. Detect CNI network from OCI spec (enter netns, read interface config, create TUN, set up NAT)
3. Spawn `litebox_broker` as a child process:
   - `--network-proxy-listen /tmp/litebox-oci-<id>.sock`
   - `--root-dir <rootfs>`
   - `--rewrite-syscalls`
   - `--read-only --writable-path /tmp`
4. Build `CliArgs`:
   - `program_and_arguments`: from OCI spec `process.args`
   - `nine_p_broker`: broker socket path (same as network-proxy-listen)
   - `network_broker`: broker socket path (same socket, LBNP vs LB9P distinguished by magic)
   - `tun_device_name`: from CNI detection or `--tun-device` CLI flag
   - `environment_variables`: from OCI spec `process.env` + extra CLI env
   - `working_directory`: from OCI spec `process.cwd`
   - `interception_backend`: Seccomp (systrap)
   - `unstable`: true (required for all flags above)
5. Call `litebox_runner_linux_userland::run(cli_args)` — diverges, does not return on success

### Lifecycle (create/start)

Ported from old runner:

- **create**: Fork. Child creates a Unix socket listener, signals parent "ready". Parent saves
  state.json with child PID. Child blocks on `accept()`.
- **start**: Parent connects to child's socket, sends "S". Child exec's into `litebox-oci run`.
- **state**: Read state.json, check if PID alive via `kill(pid, 0)`.
- **kill**: `kill(pid, signal)`.
- **delete**: Clean up state directory. Run poststop hooks.

### What's Removed vs. Old Runner

- litebox-sh binary + embedding + build.rs
- Shell name rewriting (`sh` → `litebox-sh`)
- Shebang rewriting (`#!/bin/sh` → `#!/bin/litebox-sh`)
- `add_exec_to_final_command` / `extract_command_name`
- `split_pipeline` / `run_pipeline`
- `rewrite_shell_shebang`
- Squashfs mode (mksquashfs + loop mount)
- TarLayered mode (direct tar creation from rootfs)
- LazyRewrite mode (direct rootfs walk + rewriting)
- Manual rootfs walking + file copying into in-mem FS
- Binary caching (xxhash + disk cache)
- `REQUIRE_RTLD_AUDIT` / rtld_audit.so injection

All of these are either unnecessary (fork workarounds) or handled by the broker (rootfs
loading, syscall rewriting, caching).

### What's Kept from Old Runner

- Full OCI lifecycle (lifecycle.rs) — ~580 lines
- State management (state.rs) — ~280 lines
- CLI with containerd/podman compatibility flags
- CNI auto-detection + TUN setup (~200 lines)
- Console-socket TTY support (SCM_RIGHTS PTY master)
- OCI hooks support (prestart, createRuntime, startContainer, poststart, poststop)
- `events --stats` command (read /proc/<pid>/statm and /proc/<pid>/stat)
- All unit tests (36 tests across lifecycle.rs and state.rs)

### What's New

- Broker spawning from runner.rs
- `CliArgs` construction from OCI spec
- Integration with forker process (via existing runner)
- Integration with seccomp sandbox (via existing runner)
