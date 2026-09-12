// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

//! A binary stdout reply must reach the host before the guest reads again.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::io::{BufRead as _, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use litebox::platform::{StdioOutStream, StdioProvider as _};
use litebox_platform_windows_userland::WindowsUserland;

const CHILD_ENV: &str = "LITEBOX_TEST_BINARY_STDOUT_CHILD";
const PACKET: &[u8] = b"litebox-binary-ready\0";

#[test]
fn stdio_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let platform = WindowsUserland::new();
    assert_eq!(
        platform.write_to(StdioOutStream::Stdout, PACKET).unwrap(),
        PACKET.len()
    );
    let mut reply = [0];
    std::io::stdin().read_exact(&mut reply).unwrap();
    assert_eq!(reply, [42]);
}

#[test]
fn binary_stdout_is_visible_before_next_input() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "stdio_child", "--nocapture"])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        let mut bytes = Vec::new();
        let result = reader.read_until(0, &mut bytes).map(|_| bytes);
        let _ = tx.send(result);
        // Keep draining test-harness output until the child finishes.
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });
    let result = rx.recv_timeout(Duration::from_secs(5));
    // Closing stdin also unblocks the child on assertion/error paths.
    let reply = child.stdin.take().unwrap().write_all(&[42]);
    if result.is_err() || reply.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    reader.join().unwrap();
    let bytes = result
        .expect("binary stdout was buffered while waiting for input")
        .unwrap();
    assert!(
        bytes.ends_with(PACKET),
        "unexpected child output: {bytes:?}"
    );
    assert!(reply.is_ok());
    assert!(status.success());
}
