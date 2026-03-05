// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn objdump(binary: &[u8]) -> String {
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(binary).unwrap();

    // Run objdump on the temporary file and capture the output
    let output = Command::new("objdump")
        .arg("-d")
        .arg(temp_file.path())
        .output()
        .unwrap();

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.contains("/tmp/"))
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

const HELLO_INPUT_64: &[u8] = include_bytes!("hello");
const HELLO_INPUT_32: &[u8] = include_bytes!("hello-32");
const HELLO_INPUT_AARCH64: &[u8] = include_bytes!("hello-aarch64");

fn run_snapshot_test(input: &[u8], snapshot: &str) {
    let output = litebox_syscall_rewriter::hook_syscalls_in_elf(input, None).unwrap();
    let diff = similar::udiff::unified_diff(
        similar::Algorithm::Myers,
        &objdump(input),
        &objdump(&output),
        3,
        Some(("original", "rewritten")),
    );

    insta::assert_snapshot!(snapshot, diff);
}

#[test]
#[cfg_attr(not(target_arch = "x86_64"), ignore = "x86_64-only snapshot test")]
fn snapshot_test_hello_world_x86_64() {
    run_snapshot_test(HELLO_INPUT_64, "hello-diff");
}

#[test]
#[cfg_attr(not(target_arch = "x86_64"), ignore = "x86-only snapshot test")]
fn snapshot_test_hello_world_x86() {
    run_snapshot_test(HELLO_INPUT_32, "hello-32-diff");
}

#[test]
#[cfg_attr(not(target_arch = "aarch64"), ignore = "aarch64-only snapshot test")]
fn snapshot_test_hello_world_aarch64() {
    run_snapshot_test(HELLO_INPUT_AARCH64, "hello-aarch64-diff");
}
