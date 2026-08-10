// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot `litebox_runner_optee_on_kvm` under QEMU and assert on what the guest actually did.
//!
//! # Why this lives in `dev_tests` rather than `litebox_runner_optee_on_kvm/tests/`
//!
//! `litebox_runner_optee_on_kvm` only builds for `x86_64_kvm.json`, a bare-metal
//! `no_std` target with no test harness and no way to run a host binary. A
//! `tests/` directory inside it would be compiled for that target and could
//! never execute. The harness has to be a *host* program that shells out to
//! QEMU, so it belongs with the other host-side development tests.
//!
//! # Why it is behind the `kvm_qemu` feature
//!
//! The test needs a nightly toolchain with `rust-src` (for `-Z build-std`) and
//! `qemu-system-x86_64`. The default `Build and Test` CI job has neither. The
//! target is declared in `Cargo.toml` with `required-features = ["kvm_qemu"]`,
//! so it is simply not built there, while `--all-features` sweeps still
//! type-check and clippy it. `#[ignore]` was rejected: an ignored test that
//! nobody remembers to un-ignore is indistinguishable from no test, whereas a
//! missing feature makes the CI job that needs it fail loudly if it is dropped.
//!
//! # Exit codes
//!
//! QEMU's `isa-debug-exit` turns a written value `v` into process status
//! `(v << 1) | 1`. The runner writes `0x10` on success (33) and `0x20` on
//! failure (65). `timeout(1)` reports 124 if the guest hangs.
//!
//! # The two guest paths, and why the tests reach them differently
//!
//! The runner has two ways of running a TA, and both are covered here:
//!
//! * *No virtio device on the QEMU line*: the runner logs `no virtio device`
//!   and runs `ta::run()`, its embedded, hard-coded sequence. That is still
//!   the default, and `boots_and_runs_the_ta` /
//!   `a_panicking_guest_reports_failure` drive it by building the QEMU command
//!   line here, directly, with no device.
//! * *A virtio-serial device present*: the runner hands the channel to
//!   `ta::serve()` and does nothing until a host client tells it to. Driving
//!   that needs a second process racing QEMU for a unix socket, so those tests
//!   (`a_client_drives_the_ta_over_the_channel`,
//!   `the_channel_rejects_a_command_without_a_session`) shell out to
//!   `litebox_runner_optee_on_kvm/scripts/run.sh -c` instead of reassembling that
//!   orchestration. See `run_channel_session` for the full argument.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Status QEMU exits with when the guest writes the success code.
const EXIT_SUCCESS: i32 = 33;
/// Status QEMU exits with when the guest writes the failure code.
const EXIT_FAILURE: i32 = 65;
/// Status `timeout(1)` exits with when it had to kill the guest.
const EXIT_TIMEOUT: i32 = 124;

/// Wall-clock budget for one guest run. A successful TCG run takes a few
/// seconds; this is deliberately generous, and expiring makes the test *fail*
/// rather than hang CI forever.
const GUEST_TIMEOUT_SECS: &str = "180";

/// Repository root, derived from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dev_tests must have a parent directory")
        .to_path_buf()
}

/// The nightly channel the runner pins, read from its `rust-toolchain.toml`.
///
/// Read rather than hard-coded so this test cannot drift from the crate it
/// builds. `rustup` picks a toolchain from the *current directory*, not from
/// `--manifest-path`, and we run from the repo root (whose `rust-toolchain.toml`
/// says `stable`), so the channel has to be passed explicitly as `cargo +...`.
fn runner_toolchain(root: &Path) -> String {
    let path = root.join("litebox_runner_optee_on_kvm/rust-toolchain.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let (_, channel) = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim() == "channel")
        .unwrap_or_else(|| panic!("no `channel` in {}", path.display()));
    channel.trim().trim_matches('"').to_owned()
}

/// Build the runner and return the freshly built binary.
///
/// This is the answer to the stale-binary risk: the test never consumes an
/// artifact it did not just ask `cargo` to bring up to date. Cargo is the
/// freshness authority, so "the build succeeded" *is* "the binary matches the
/// sources". A build failure, a missing toolchain or a missing output all
/// panic with the captured output rather than falling back to whatever happens
/// to be lying in `target/`.
fn build_runner(root: &Path) -> PathBuf {
    let toolchain = runner_toolchain(root);
    let output = Command::new("cargo")
        .current_dir(root)
        .args([
            &format!("+{toolchain}"),
            "build",
            "--locked",
            "-Z",
            "build-std-features=compiler-builtins-mem",
            "-Z",
            "build-std=core,alloc",
            "--manifest-path=litebox_runner_optee_on_kvm/Cargo.toml",
            "--target",
            "litebox_runner_optee_on_kvm/x86_64_kvm.json",
        ])
        .output()
        .expect("failed to spawn `cargo`; is it on PATH?");
    assert!(
        output.status.success(),
        "building litebox_runner_optee_on_kvm failed ({}).\n\
         Requires the `{toolchain}` toolchain with the `rust-src` component.\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let binary = root.join("target/x86_64_kvm/debug/litebox_runner_optee_on_kvm");
    assert!(
        binary.is_file(),
        "cargo reported success but {} does not exist",
        binary.display(),
    );
    binary
}

/// Boot `binary` under QEMU with `memory` of RAM; return `(exit status, console)`.
///
/// TCG only, deliberately: no `-enable-kvm`, so this needs no privileges and no
/// `/dev/kvm`, which GitHub-hosted runners do not expose. `-cpu max` is
/// required even under TCG because the default `qemu64` model lacks `RDRAND`,
/// which the guest's `CrngProvider` needs.
///
/// The bounded wait is `timeout(1)`: it kills QEMU, which closes the pipe,
/// which lets the blocking read below finish. Reading to EOF *without* that
/// outer kill would be an unbounded wait, i.e. a hung CI job.
fn run_guest(binary: &Path, memory: &str) -> (i32, String) {
    let output = Command::new("timeout")
        .args([
            "--foreground",
            "--kill-after=10",
            GUEST_TIMEOUT_SECS,
            "qemu-system-x86_64",
            "-machine",
            "q35",
            "-cpu",
            "max",
            "-m",
            memory,
            "-kernel",
            binary.to_str().expect("binary path must be UTF-8"),
            "-nographic",
            "-no-reboot",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .output()
        .expect("failed to spawn `timeout`/`qemu-system-x86_64`; is QEMU installed?");

    let mut console = String::from_utf8_lossy(&output.stdout).into_owned();
    console.push_str(&String::from_utf8_lossy(&output.stderr));
    let console = console.replace('\r', "");

    let status = output
        .status
        .code()
        .unwrap_or_else(|| panic!("qemu was killed by a signal: {}", output.status));
    assert_ne!(
        status, EXIT_TIMEOUT,
        "guest did not exit within {GUEST_TIMEOUT_SECS}s.\n--- console ---\n{console}",
    );
    (status, console)
}

/// Assert `console` contains `needle`, printing the whole console if not.
fn assert_console_contains(console: &str, needle: &str) {
    assert!(
        console.contains(needle),
        "expected {needle:?} in the guest console.\n--- console ---\n{console}",
    );
}

/// The success path *of the no-device configuration*: with no virtio device on
/// the QEMU line the runner falls back to `ta::run()`, its embedded sequence,
/// which boots, loads `ldelf`, runs `hello-ta` in ring 3 and exits with the
/// success code.
///
/// That fallback is still the default and still the only path that needs no
/// host-side peer, so it keeps its own test even now that the channel exists;
/// `a_client_drives_the_ta_over_the_channel` covers `ta::serve()` alongside it.
/// Note the QEMU line below deliberately has no `-device virtio-serial-pci`:
/// adding one here would silently move this test onto the *other* path and
/// leave the embedded sequence untested, which is what the `no virtio device`
/// assertion below is there to prevent.
///
/// The exit status alone would be far too weak a claim -- a guest that reached
/// long mode and immediately wrote `0x10` would satisfy it -- so this also
/// pins the TA's own output, which can only appear if the OP-TEE syscall path
/// carried it back out of ring 3.
#[test]
fn boots_and_runs_the_ta() {
    let root = repo_root();
    let binary = build_runner(&root);
    let (status, console) = run_guest(&binary, "512M");

    assert_console_contains(&console, "no virtio device");
    assert_console_contains(&console, "Hello World!");
    assert_console_contains(&console, "Goodbye!");
    assert_console_contains(&console, "TA CloseSession returned");
    assert_console_contains(&console, "DEP is enforced and the run is complete");
    assert_eq!(
        status, EXIT_SUCCESS,
        "expected the success exit status.\n--- console ---\n{console}",
    );
}

/// The failure path: a panicking guest must report failure, not success.
///
/// Without this, the success test only proves the runner *can* exit with 33; it
/// says nothing about whether 33 is ever *withheld*. The panic is provoked
/// entirely from the QEMU command line -- 32 MiB of RAM is not enough for the
/// heap self-check's 3 MiB allocation -- so the product build is untouched: no
/// second binary, no cargo feature and no "am I under test?" branch in the
/// runner. The cost is that this is coupled to a specific allocation size, so a
/// future change to the self-checks could turn it into a *pass* for the wrong
/// reason; the assertions on the panic text and on the sizing of the memory are
/// there to make that show up as a failure rather than pass silently.
#[test]
fn a_panicking_guest_reports_failure() {
    let root = repo_root();
    let binary = build_runner(&root);
    let (status, console) = run_guest(&binary, "32M");

    assert_console_contains(&console, "PANIC:");
    assert_console_contains(&console, "memory allocation of");
    assert_eq!(
        status, EXIT_FAILURE,
        "expected the failure exit status.\n--- console ---\n{console}",
    );
}

// ---------------------------------------------------------------------------
// The virtio message channel.
// ---------------------------------------------------------------------------

/// Wall-clock budget handed to `run.sh -t`, covering both the guest and the
/// client's bounded connect retry. A whole channel session takes about ten
/// seconds under TCG.
const CHANNEL_TIMEOUT_SECS: &str = "90";

/// Status `run.sh` exits with when the client reported a failure.
///
/// The script prefers the client's verdict to the guest's, because the client
/// is the side that knows what went wrong with the exchange.
const SCRIPT_CLIENT_FAILURE: i32 = 1;

/// A private directory for one channel test's socket and command file.
///
/// Two things need to be unique per test. The unix socket, because two QEMUs
/// binding the same path would collide; and the command file, because each
/// test drives a different sequence. The `kvm-qemu` nextest group
/// (`max-threads = 1`, see `.config/nextest.toml`) already serialises this
/// binary, so uniqueness is belt and braces -- but it is cheap, and it means a
/// developer running two `cargo test` invocations side by side, or a future
/// edit to that group, cannot produce a confusing cross-test failure.
fn scratch_dir(test_name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "litebox-kvm-channel-{test_name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
    dir
}

/// Fail loudly and early if `python3` is missing, rather than inside QEMU.
///
/// `run.sh` also checks, but only after it has built and while its message is
/// competing with a guest's serial log for attention. Checking here means the
/// test's *first* line of output says what is wrong.
fn require_python3() {
    let found = Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    assert!(
        found,
        "`python3` is required: the channel tests drive the guest with \
         litebox_runner_optee_on_kvm/scripts/client.py, which is the only host-side \
         implementation of the wire protocol. Install python3 (it is \
         preinstalled on GitHub-hosted runners) or skip these tests.",
    );
}

/// Drive one channel session with `commands`; return `(exit status, output)`.
///
/// # Why this shells out to `scripts/run.sh` and `scripts/client.py`
///
/// The channel needs three things the other tests do not: a virtio-serial
/// device and unix-socket chardev on the QEMU line, a second process speaking
/// the protocol, and a bounded retry because QEMU is the socket *server* and
/// the client necessarily races its creation. `run.sh -c` already does all
/// three. Reimplementing the protocol in Rust here was the alternative and was
/// rejected twice over: it would be a second encoder/decoder to keep in step
/// with `src/proto.rs` by hand, and -- worse -- it would leave `run.sh` and
/// `client.py`, the path every developer actually uses, with no test at all,
/// free to rot until someone tried them. Shelling out means the tested path
/// and the developer path are the same path.
///
/// The cost is the `python3` dependency, which `require_python3` turns into a
/// clear assertion rather than a mysterious one.
///
/// `-s` skips the script's own build: the caller has already built through
/// `build_runner`, which is the function that owns the "never run a stale
/// binary" guarantee. Letting the script rebuild would be harmless but would
/// put a second, differently-spelled build command in the freshness story.
///
/// The outer `timeout` is a backstop. `run.sh -t` bounds the guest and the
/// client individually, so this should never be what fires; if it does, the
/// script's own bounding is broken, and 124 says so distinctly instead of
/// hanging the job.
fn run_channel_session(root: &Path, name: &str, commands: &str) -> (i32, String) {
    let dir = scratch_dir(name);
    let command_file = dir.join("commands.json");
    std::fs::write(&command_file, commands)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", command_file.display()));
    let out = run_channel_session_with(root, &dir, &ta_artifact("hello-ta.elf"), &command_file);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// The unrewritten OP-TEE artifact `name`, from the userland runner's tests.
///
/// Unrewritten is the whole point: `litebox_runner_optee_on_linux_userland`'s
/// own `run.rs` puts both binaries through `litebox_syscall_rewriter` first,
/// because on Linux userland LiteBox is a library and syscalls have to be
/// hooked by rewriting them. Under KVM LiteBox is the kernel: a TA's real
/// `syscall` instructions trap to `syscall_entry`, and the rewriter's output
/// would be the wrong binary.
fn ta_artifact(name: &str) -> PathBuf {
    let path = repo_root()
        .join("litebox_runner_optee_on_linux_userland/tests")
        .join(name);
    assert!(path.is_file(), "{} does not exist", path.display());
    path
}

/// Drive one channel session against `ta` with the sequence in `command_file`.
fn run_channel_session_with(
    root: &Path,
    dir: &Path,
    ta: &Path,
    command_file: &Path,
) -> (i32, String) {
    run_channel_session_with_memory(root, dir, ta, command_file, None)
}

/// As [`run_channel_session_with`], but optionally overriding the guest's
/// memory size (`run.sh -m`).
///
/// Only [`many_open_close_cycles_do_not_exhaust_the_guest`] passes `Some`. It
/// needs a *small* guest, because the resource it is watching is reclaimed per
/// session and the only way to see it not being reclaimed is to run out.
fn run_channel_session_with_memory(
    root: &Path,
    dir: &Path,
    ta: &Path,
    command_file: &Path,
    memory: Option<&str>,
) -> (i32, String) {
    require_python3();
    let binary = build_runner(root);
    assert!(binary.is_file(), "{} vanished", binary.display());

    let socket = dir.join("optee.sock");
    let ldelf = ta_artifact("ldelf.elf");

    let script = root.join("litebox_runner_optee_on_kvm/scripts/run.sh");
    assert!(script.is_file(), "{} does not exist", script.display());

    let mut command = Command::new("timeout");
    command.current_dir(root).args([
        "--foreground",
        "--kill-after=10",
        GUEST_TIMEOUT_SECS,
        script.to_str().expect("script path must be UTF-8"),
        "-s",
        "-t",
        CHANNEL_TIMEOUT_SECS,
        "-c",
        command_file.to_str().expect("command path must be UTF-8"),
        "-l",
        ldelf.to_str().expect("ldelf path must be UTF-8"),
        "-a",
        ta.to_str().expect("TA path must be UTF-8"),
        "-S",
        socket.to_str().expect("socket path must be UTF-8"),
    ]);
    if let Some(memory) = memory {
        command.args(["-m", memory]);
    }

    let output = command
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn `timeout`/`run.sh`; is QEMU installed?");

    let mut console = String::from_utf8_lossy(&output.stdout).into_owned();
    console.push_str(&String::from_utf8_lossy(&output.stderr));
    let console = console.replace('\r', "");

    let status = output
        .status
        .code()
        .unwrap_or_else(|| panic!("run.sh was killed by a signal: {}", output.status));
    assert_ne!(
        status, EXIT_TIMEOUT,
        "the channel session did not finish within {GUEST_TIMEOUT_SECS}s, so \
         run.sh's own -t {CHANNEL_TIMEOUT_SECS} bound did not hold.\n\
         --- output ---\n{console}",
    );
    (status, console)
}

/// The channel success path: a host client opens a session, invokes two
/// commands and closes it, and the TA's *own* arithmetic comes back.
///
/// `hello-ta` increments the first `value_inout` on command 0 and decrements
/// it on command 1, so 100 comes back as 101 (`0x65`) and 200 as 199
/// (`0xc7`). Those two numbers are the point of the test. An exit status, or
/// even a `status=0` reply, would be satisfied by a runner that acknowledged
/// the requests and ran nothing; `0x65` and `0xc7` can only appear if the
/// request was decoded into `UteeParams`, the TA really executed in ring 3,
/// and its *output* parameters were read back out of user memory and encoded
/// into the reply. That is the whole channel, end to end.
///
/// The sequence is the same one `hello-ta-cmds.json` holds for the userland
/// runner, restated inline rather than read from that crate: the assertions
/// below hard-code the results of 100 and 200, so a test that loaded its
/// inputs from a file somebody else owns could quietly start checking
/// arithmetic on numbers that are no longer the ones it was given.
#[test]
fn a_client_drives_the_ta_over_the_channel() {
    let root = repo_root();
    let commands = r#"[
      { "func_id": "open_session", "client_identity": { "login": "user" } },
      { "func_id": "invoke_command", "cmd_id": 0,
        "args": [ { "param_type": "value_inout", "value_a": 100, "value_b": 0 } ] },
      { "func_id": "invoke_command", "cmd_id": 1,
        "args": [ { "param_type": "value_inout", "value_a": 200, "value_b": 0 } ] },
      { "func_id": "close_session" }
    ]"#;
    let (status, console) = run_channel_session(&root, "drives-the-ta", commands);

    // The guest took the channel path, not the embedded fallback.
    assert_console_contains(&console, "channel    serving requests");
    // The TA's own results, read back out of ring 3.
    assert_console_contains(&console, "[0] value_inout value_a=0x65");
    assert_console_contains(&console, "[0] value_inout value_a=0xc7");
    // The client, and then the guest, both got all the way to the end.
    assert_console_contains(&console, "[client] sequence completed");
    assert_console_contains(&console, "Guest completed successfully");
    assert_eq!(
        status, 0,
        "expected run.sh to report success.\n--- output ---\n{console}",
    );
}

/// The channel failure path: a request that arrives out of order is refused,
/// cleanly and immediately.
///
/// Without this, `a_client_drives_the_ta_over_the_channel` only proves the
/// runner *can* answer `status=0`; it says nothing about whether success is
/// ever withheld, and a `serve()` loop that replied `status=0` to everything
/// would pass it. `InvokeCommand` with no preceding `OpenSession` is the
/// cheapest way to ask for something the runner must refuse.
///
/// "Cleanly" is the load-bearing word, and is why the exit status is checked
/// too. The refusal must be a *reply* -- the runner keeps serving, the client
/// gets a diagnosis, and both sides end in a few seconds. A guest that
/// panicked, or one that dropped the frame and left the client blocked on a
/// read until the deadline, would also "not succeed", and neither is
/// acceptable. Those outcomes stay distinguishable: a panic exits 65 through
/// the guest branch of `run.sh` rather than 1 through the client branch, and a
/// hang trips `EXIT_TIMEOUT` in `run_channel_session` with a message that says
/// which bound failed.
#[test]
fn the_channel_rejects_a_command_without_a_session() {
    let root = repo_root();
    let commands = r#"[
      { "func_id": "invoke_command", "cmd_id": 0,
        "args": [ { "param_type": "value_inout", "value_a": 100, "value_b": 0 } ] }
    ]"#;
    let (status, console) = run_channel_session(&root, "no-session", commands);

    // The runner rejected it, and said why, in a reply rather than by dying.
    assert_console_contains(&console, "channel    response error: no session is open");
    assert_console_contains(&console, "[client] <- status=1");
    assert_console_contains(&console, "[client] FAILED: InvokeCommand failed");
    // It really did refuse: the TA never ran.
    assert!(
        !console.contains("value_inout value_a=0x65"),
        "the TA ran despite there being no session.\n--- output ---\n{console}",
    );
    assert_eq!(
        status, SCRIPT_CLIENT_FAILURE,
        "expected run.sh to report the client's failure.\n--- output ---\n{console}",
    );
}

/// Sessions are cheap to open and close repeatedly, because closing one gives
/// its resources back.
///
/// # What used to happen
///
/// `ta::open_session` called `SessionToken::disarm()` without the
/// `register_new_session` that makes disarming correct, and nothing ever
/// released the user mappings `load_ldelf` made. So every open/close pair
/// stranded a session id, a client-identity map entry, and -- overwhelmingly
/// the largest of the three -- about 1.3 MiB of ldelf and TA images that stayed
/// mapped for the rest of the boot. Measured before the fix, with
/// `open_session` / `close_session` pairs and nothing else:
///
/// | guest memory | died on session |
/// |--------------|-----------------|
/// | 512 MiB      | 416             |
/// | 64 MiB       | 27              |
///
/// with a `handle_alloc_error` panic out of the guest's allocator. After the
/// fix, 600 pairs complete at *both* sizes and the guest's post-run heap probe
/// lands at the same address either way -- the heap does not grow at all.
///
/// # Why 64 MiB and [`OPEN_CLOSE_CYCLES`] cycles
///
/// The leak was a *rate*, so a test for it has to be a race between that rate
/// and a bound. Shrinking the bound is much cheaper than lengthening the run:
/// at 512 MiB it takes over 400 sessions to prove anything, at 64 MiB it takes
/// 27. [`OPEN_CLOSE_CYCLES`] is set several times higher than 27 so that a
/// partial regression -- something that leaks less per session than the
/// original did -- is still caught, and the whole test still runs in about ten
/// seconds under TCG because a session costs far less than the boot does.
///
/// 64 MiB is the smallest round size this guest boots in at all; 48 MiB fails
/// during bring-up, before any session exists.
///
/// # Why the assertion is on the *last* session, not just the exit status
///
/// A guest that answered `status=0` to the first request and then quietly
/// stopped opening sessions would exit cleanly. So the console is checked for
/// the TA's own arithmetic on the final cycle: `hello-ta` turns 100 into 101,
/// and that line can only appear if session number [`OPEN_CLOSE_CYCLES`]
/// really loaded, entered ring 3 and returned its output parameter.
#[test]
fn many_open_close_cycles_do_not_exhaust_the_guest() {
    /// How many open/invoke/close cycles the client drives.
    const OPEN_CLOSE_CYCLES: usize = 120;
    /// Guest memory for this test. See the function's documentation.
    const GUEST_MEMORY: &str = "64M";

    let root = repo_root();
    let dir = scratch_dir("open-close-cycles");
    let command_file = dir.join("commands.json");

    let mut commands = String::from("[\n");
    for cycle in 0..OPEN_CLOSE_CYCLES {
        if cycle > 0 {
            commands.push_str(",\n");
        }
        commands.push_str(
            r#"  { "func_id": "open_session", "client_identity": { "login": "user" } },
  { "func_id": "invoke_command", "cmd_id": 0,
    "args": [ { "param_type": "value_inout", "value_a": 100, "value_b": 0 } ] },
  { "func_id": "close_session" }"#,
        );
    }
    commands.push_str("\n]\n");
    std::fs::write(&command_file, &commands)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", command_file.display()));

    let (status, console) = run_channel_session_with_memory(
        &root,
        &dir,
        &ta_artifact("hello-ta.elf"),
        &command_file,
        Some(GUEST_MEMORY),
    );
    let _ = std::fs::remove_dir_all(&dir);

    assert_console_contains(&console, "channel    serving requests");
    // Every cycle ran the TA and every cycle got its answer back. Counting
    // rather than merely finding one: a guest that stopped after the first
    // session would still contain the line once.
    let ran = console.matches("value_inout value_a=0x65").count();
    assert_eq!(
        ran, OPEN_CLOSE_CYCLES,
        "only {ran} of {OPEN_CLOSE_CYCLES} cycles reached the TA.\n\
         --- output ---\n{console}",
    );
    // And every one of them was closed cleanly, releasing its mappings and id.
    let closed = console.matches("user mappings and id released").count();
    assert_eq!(
        closed, OPEN_CLOSE_CYCLES,
        "only {closed} of {OPEN_CLOSE_CYCLES} sessions were torn down.\n\
         --- output ---\n{console}",
    );
    assert_console_contains(&console, "[client] sequence completed");
    assert_console_contains(&console, "Guest completed successfully");
    assert_eq!(
        status, 0,
        "the guest did not survive {OPEN_CLOSE_CYCLES} open/close cycles in \
         {GUEST_MEMORY}.\n--- output ---\n{console}",
    );
}

// ---------------------------------------------------------------------------
// The five TAs, mirroring `litebox_runner_optee_on_linux_userland/tests/run.rs`.
//
// Same five binaries, same five command sequences, read from the same
// directory -- but *unrewritten*, and driven over the channel rather than
// in-process. The verification standard is the userland runner's: the client
// raises, and `run.sh` exits non-zero, if any command comes back with a
// non-zero `ta_return` or a non-zero runner status, so `status == 0` below is
// exactly "every command's `ctx.rax` was 0". Each test then adds an assertion
// on something only that TA could have produced, because an exit status alone
// would be satisfied by a runner that acknowledged the requests and ran
// nothing.
// ---------------------------------------------------------------------------

/// Run `{name}.elf` against `{name}-cmds.json`, the pair `run.rs` runs.
fn run_ta(name: &str) -> (i32, String) {
    let root = repo_root();
    let dir = scratch_dir(name);
    let ta = ta_artifact(&format!("{name}.elf"));
    let commands = ta_artifact(&format!("{name}-cmds.json"));
    let out = run_channel_session_with(&root, &dir, &ta, &commands);
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Assert the session succeeded, i.e. every command returned `ta_return == 0`.
fn assert_ta_succeeded(name: &str, status: i32, console: &str) {
    assert_console_contains(console, "channel    serving requests");
    assert_console_contains(console, "[client] sequence completed");
    assert_console_contains(console, "Guest completed successfully");
    assert_eq!(
        status, 0,
        "{name} did not complete cleanly.\n--- output ---\n{console}",
    );
}

/// `hello-ta` over the channel, from the shipped binary rather than the
/// embedded one.
///
/// `a_client_drives_the_ta_over_the_channel` already covers this arithmetic
/// with an inline sequence; this covers the *file*, so a change to
/// `hello-ta-cmds.json` that the other test's hard-coded 100 and 200 would
/// hide shows up here.
#[test]
fn runs_the_hello_ta() {
    let (status, console) = run_ta("hello-ta");
    assert_console_contains(&console, "Hello World!");
    assert_console_contains(&console, "Goodbye!");
    // 100 -> 101 and 200 -> 199, the TA's own arithmetic read back out of
    // ring 3.
    assert_console_contains(&console, "value_inout value_a=0x65");
    assert_console_contains(&console, "value_inout value_a=0xc7");
    assert_ta_succeeded("hello-ta", status, &console);
}

/// `random-ta`, the first TA here to fill a `memref_output`.
///
/// `-cpu max` is required and `run.sh` supplies it: the default `qemu64` model
/// has no `RDRAND` and the guest's `CrngProvider` needs it.
#[test]
fn runs_the_random_ta() {
    let (status, console) = run_ta("random-ta");
    assert_console_contains(&console, "Generating random data over 64 bytes.");
    // All 64 bytes came back. The buffer was sent empty and 64 bytes long, so
    // this can only be what the TA wrote into user memory.
    assert_console_contains(&console, "memref_output buffer_size=64 len=64 hex=");
    assert!(
        !console.contains(&"00".repeat(64)),
        "the 64 'random' bytes are all zero, so nothing was written.\n\
         --- output ---\n{console}",
    );
    assert_ta_succeeded("random-ta", status, &console);
}

/// `aes-ta`, and the strongest claim in this file.
///
/// The sequence sets AES-128-CTR up, loads a key and an IV, and enciphers 32
/// bytes. The expected ciphertext below is not copied from a passing run: it
/// is what AES-128-CTR produces for that key, IV and plaintext, computed
/// independently. So it holds the whole memref path to an external standard --
/// a `memref_input` that reached the TA byte-exact and a `memref_output` read
/// back out of ring 3 byte-exact -- rather than to whatever this port happens
/// to do.
///
///     key        9f4ff5a1c4ea8d662407078db96e3b28
///     iv         13005df291b9e575b0ab2a7a0a06b5f4
///     plaintext  428224303f3d80b2cc52bcee17e9cb09325a8a45ec842c2cfc85797133f5185a
#[test]
fn runs_the_aes_ta() {
    let (status, console) = run_ta("aes-ta");
    assert_console_contains(
        &console,
        "memref_output buffer_size=32 len=32 \
         hex=4ccc41d75eb8e3b316fdf0eaa358384366f8d878e040f448bf695dd37ae40068",
    );
    assert_ta_succeeded("aes-ta", status, &console);
}

/// `kmpp-ta`, and the test that changed meaning when the platform grew a root
/// key.
///
/// It used to assert the *opposite* of what it asserts now. `DerivedKeyProvider`
/// for `KvmGuest` returned `UnsupportedRebootPersistentKey`,
/// `litebox_shim_optee/src/syscalls/pta.rs` mapped that to
/// `TeeResult::NotSupported`, and the TA saw `0xffff000a` out of
/// `derive_unique_key`, logged `Failed to get machine secret`, could not
/// encrypt the private key it was asked to import, and reported that failure
/// inside the output memref while `TA_InvokeCommandEntryPoint` itself returned
/// 0. The test pinned that refusal deliberately, so that whoever installed a
/// key would be forced to come and read this comment. That has now happened.
///
/// `litebox_platform_lvbs::host::kvm::install_development_platform_root_key`
/// installs an emulated PRK at boot, so derivation takes the real path and
/// `KeyIso_SERVER_import_private_key` runs to completion. The assertions below
/// are the inverses of the old ones: the two failure lines must be *absent*,
/// and the TA's own completion line must be present and say `Success`.
///
/// The reason to assert on absence as well as presence is that
/// `TA_InvokeCommandEntryPoint` returned 0 in the failing case too, so
/// `assert_ta_succeeded` alone never distinguished the two. It still does not;
/// these assertions are what make this test mean anything.
///
/// **The key has no security value.** It is SHA-256 of a fixed ASCII string
/// compiled into the image, and the guest warns three lines about that on every
/// boot. What this test now demonstrates is that the *derivation path* works,
/// not that anything is sealed against anybody.
#[test]
fn runs_the_kmpp_ta() {
    let (status, console) = run_ta("kmpp-ta");
    // The TA really ran: it imports an EC private key twice, opening and
    // closing a session around each.
    assert_console_contains(&console, "KeyIso_SERVER_import_private_key");
    // ... and this time it got all the way through, which it cannot do without
    // a derived key.
    assert_console_contains(&console, "_cleanup_import_private_key");
    assert_console_contains(&console, "Complete- Success");
    // The two lines the refusal used to produce. `ffff000a` is
    // TEE_ERROR_NOT_SUPPORTED. If either comes back, derivation has regressed
    // to the refusal path and the assertions above are not enough to catch it
    // on their own.
    assert!(
        !console.contains("derive_unique_key failed"),
        "the platform refused a derived key; it is supposed to install one at boot.\n\
         --- output ---\n{console}",
    );
    assert!(
        !console.contains("Failed to get machine secret"),
        "the TA could not get a machine secret, so derivation did not reach it.\n\
         --- output ---\n{console}",
    );
    // And the boot-time warning is part of the contract: a fake root key that
    // installs quietly is the failure mode the warning exists to prevent.
    assert_console_contains(
        &console,
        "DEVELOPMENT platform root key with NO SECURITY VALUE",
    );
    assert_ta_succeeded("kmpp-ta", status, &console);
}
