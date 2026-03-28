// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Central process management for the launcher.
//!
//! Forks a child process to run `litebox_central`, passing the shared memory
//! file descriptor so that both processes share the same IPC ring buffer.

/// A handle to a forked `litebox_central` child process.
#[allow(dead_code)] // Used by launcher orchestration in later phases
pub struct CentralProcess {
    pid: i32,
}

#[allow(dead_code)] // Methods used by launcher orchestration in later phases
impl CentralProcess {
    /// Spawn `litebox_central` as a child process, passing the shared memory fd.
    ///
    /// The child inherits `shmem_fd` (which must NOT have `CLOEXEC` set) and
    /// execs `litebox_central` with `--shmem-fd=<N>` as the first argument.
    ///
    /// Note: `litebox_central` currently creates its own shared memory. Accepting
    /// an external fd is a TODO for the integration phase. For now, the child
    /// immediately exits.
    ///
    /// # Safety
    ///
    /// This function calls `libc::fork()`. The caller must ensure that forking
    /// is safe in the current process state (e.g. no other threads holding
    /// locks that the child would inherit in a locked state).
    pub fn spawn(shmem_fd: i32) -> anyhow::Result<Self> {
        let _ = shmem_fd; // Will be used when litebox_central accepts --shmem-fd

        // SAFETY: We call `fork()` which is safe here because the launcher is
        // single-threaded at the point of spawning. The child immediately exits
        // (and will eventually exec `litebox_central`).
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child: exec litebox_central with the shmem fd as an argument.
                // Convention: pass fd number as first CLI arg.
                // TODO: actually exec litebox_central once it accepts --shmem-fd=N
                std::process::exit(0);
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
        let proc = CentralProcess::spawn(0).expect("spawn should succeed");
        assert!(proc.pid() > 0);
        let mut status: i32 = 0;
        // SAFETY: `proc.pid()` is a valid child PID returned by `fork()`.
        // We pass a valid pointer to `status` and wait for this specific child.
        let ret = unsafe { libc::waitpid(proc.pid(), &mut status, 0) };
        assert_eq!(ret, proc.pid());
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}
