// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Boot `litebox_runner_kvm` under QEMU and assert on what the guest actually did.
//!
//! # Why this lives in `dev_tests` rather than `litebox_runner_kvm/tests/`
//!
//! `litebox_runner_kvm` only builds for `x86_64_kvm.json`, a bare-metal
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
    let path = root.join("litebox_runner_kvm/rust-toolchain.toml");
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
            "--manifest-path=litebox_runner_kvm/Cargo.toml",
            "--target",
            "litebox_runner_kvm/x86_64_kvm.json",
        ])
        .output()
        .expect("failed to spawn `cargo`; is it on PATH?");
    assert!(
        output.status.success(),
        "building litebox_runner_kvm failed ({}).\n\
         Requires the `{toolchain}` toolchain with the `rust-src` component.\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let binary = root.join("target/x86_64_kvm/debug/litebox_runner_kvm");
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

/// The success path: the guest boots, loads `ldelf`, runs `hello-ta` in ring 3
/// and exits with the success code.
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
