// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central process management for the launcher.
//!
//! Forks a child process to run `litebox_central`, passing the shared memory
//! file descriptor so that both processes share the same IPC ring buffer.

use std::ffi::CString;

/// A handle to a forked `litebox_central` child process.
#[allow(dead_code)] // Used by launcher orchestration in later phases
pub struct CentralProcess {
    pid: i32,
}

/// Find the `litebox_central` binary using path heuristics.
///
/// Resolution order:
/// 1. `LITEBOX_CENTRAL_PATH` environment variable (explicit override).
/// 2. Same directory as the current executable.
/// 3. Fall back to bare name (relies on `$PATH` lookup by `execvp`).
fn find_central_binary() -> String {
    // Check LITEBOX_CENTRAL_PATH env var first
    if let Ok(path) = std::env::var("LITEBOX_CENTRAL_PATH") {
        return path;
    }
    // Check same directory as current executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("litebox_central");
        if candidate.exists() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    // Fall back to PATH lookup
    "litebox_central".to_string()
}

#[allow(dead_code)] // Methods used by launcher orchestration in later phases
impl CentralProcess {
    /// Spawn `litebox_central` as a child process, passing the shared memory fd.
    ///
    /// The child inherits `shmem_fd` (which must NOT have `CLOEXEC` set) and
    /// execs `litebox_central` with `--shmem-fd=<N>` as the first argument.
    ///
    /// # Safety
    ///
    /// This function calls `libc::fork()`. The caller must ensure that forking
    /// is safe in the current process state (e.g. no other threads holding
    /// locks that the child would inherit in a locked state).
    pub fn spawn(shmem_fd: i32, initial_brk: usize, rootfs_tar: Option<&str>) -> anyhow::Result<Self> {
        // SAFETY: We call `fork()` which is safe here because the launcher is
        // single-threaded at the point of spawning. The child either execs
        // `litebox_central` or exits on failure.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child: redirect stdout/stderr to /dev/null so that central
                // does not hold the parent's pipe handles open (which would
                // prevent Command::output() from returning in tests).
                // Skip if shmem_fd is 1 or 2 to avoid clobbering it.
                if shmem_fd != 1 && shmem_fd != 2 {
                    let devnull = unsafe {
                        libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC)
                    };
                    if devnull >= 0 {
                        unsafe {
                            libc::dup2(devnull, 1);
                            // Keep stderr for now — central may need diagnostics.
                            // In production, redirect stderr to a log file.
                            libc::close(devnull);
                        }
                    }
                }

                // Exec litebox_central with the shmem fd and initial brk as arguments.
                let fd_arg = format!("--shmem-fd={shmem_fd}");
                let brk_arg = format!("--initial-brk={initial_brk}");
                let central_path = find_central_binary();
                let c_path = CString::new(central_path).unwrap();
                let c_name = CString::new("litebox_central").unwrap();
                let c_fd = CString::new(fd_arg).unwrap();
                let c_brk = CString::new(brk_arg).unwrap();

                let mut c_args = vec![c_name, c_fd, c_brk];

                if let Some(tar_path) = rootfs_tar {
                    c_args.push(CString::new(format!("--rootfs-tar={tar_path}")).unwrap());
                }

                let mut arg_ptrs: Vec<*const libc::c_char> =
                    c_args.iter().map(|a| a.as_ptr()).collect();
                arg_ptrs.push(std::ptr::null());

                // SAFETY: `c_path` and `arg_ptrs` are valid C strings / null-
                // terminated array. The `c_args` Vec keeps the CStrings alive
                // for the duration of the `execvp` call. On success `execvp`
                // never returns.
                unsafe { libc::execvp(c_path.as_ptr(), arg_ptrs.as_ptr()) };
                // If exec fails:
                eprintln!(
                    "litebox_launcher: exec litebox_central failed: {}",
                    std::io::Error::last_os_error()
                );
                // SAFETY: We are in the forked child after a failed exec. Using
                // `_exit` avoids running atexit handlers / flushing stdio
                // buffers that belong to the parent.
                unsafe { libc::_exit(1) };
            }
            _ => Ok(CentralProcess { pid }),
        }
    }

    /// Returns the PID of the child process.
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_and_wait() {
        let proc = CentralProcess::spawn(0, 0, None).expect("spawn should succeed");
        assert!(proc.pid() > 0);
        let mut status: i32 = 0;
        // SAFETY: `proc.pid()` is a valid child PID returned by `fork()`.
        // We pass a valid pointer to `status` and wait for this specific child.
        let ret = unsafe { libc::waitpid(proc.pid(), &mut status, 0) };
        assert_eq!(ret, proc.pid());
        assert!(libc::WIFEXITED(status));
        // The child tries to exec `litebox_central`, which is not available in
        // the test environment, so it falls back to _exit(1).
        assert_eq!(libc::WEXITSTATUS(status), 1);
    }
}
