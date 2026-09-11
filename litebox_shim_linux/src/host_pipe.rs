//! Dedicated byte streams between a host and a loaded guest.
//!
//! Guest descriptors use normal Linux read/write/poll/close semantics. Host
//! endpoints own their handles and close them on drop. Each endpoint has its
//! own wait state; it can move to an I/O thread but cannot be shared concurrently.

use alloc::sync::Arc;
use litebox::{event::wait::WaitState, fs::OFlags, pipes::PipeFd};
use litebox_common_linux::errno::Errno;

use crate::{GlobalState, LoadedProgram, ShimPlatform, Task};

struct Endpoint<P: ShimPlatform> {
    global: Arc<GlobalState<P>>,
    fd: PipeFd<P>,
    wait: WaitState<P>,
}

impl<P: ShimPlatform> Drop for Endpoint<P> {
    fn drop(&mut self) {
        let _ = self.global.close_linux_pipe(&self.fd);
    }
}

/// Host side of a pipe carrying bytes produced by the guest.
pub struct HostReader<P: ShimPlatform>(Endpoint<P>);

impl<P: ShimPlatform> HostReader<P> {
    /// Blocks until data or EOF. Returns zero after the guest closes its writer.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno> {
        self.0
            .global
            .read_linux_pipe(&self.0.wait.context(), &self.0.fd, buf)
    }
}

/// Host side of a pipe carrying bytes consumed by the guest.
pub struct HostWriter<P: ShimPlatform>(Endpoint<P>);

impl<P: ShimPlatform> HostWriter<P> {
    /// Blocks for pipe capacity; returns EPIPE when the guest reader closes.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, Errno> {
        self.0
            .global
            .write_linux_pipe(&self.0.wait.context(), &self.0.fd, buf)
    }
}

impl<P: ShimPlatform> LoadedProgram<P> {
    /// Allocate a guest read descriptor and return the host writer.
    ///
    /// Call before starting the guest. The returned descriptor is allocated from
    /// the guest table, never assumed to be 3 or 4. It is inherited across exec.
    pub fn attach_host_input(&mut self) -> Result<(u32, HostWriter<P>), Errno> {
        self.entrypoints.task.attach_host_input()
    }

    /// Allocate a guest write descriptor and return the host reader.
    /// Call before starting the guest; standard streams remain untouched.
    pub fn attach_host_output(&mut self) -> Result<(u32, HostReader<P>), Errno> {
        self.entrypoints.task.attach_host_output()
    }
}

impl<P: ShimPlatform> Task<P> {
    fn attach_host_pipe(&self, guest_reads: bool) -> Result<(u32, Endpoint<P>), Errno> {
        let ends = self.global.create_linux_pipe(OFlags::empty())?;
        let (guest, host) = if guest_reads {
            (ends.reader, ends.writer)
        } else {
            (ends.writer, ends.reader)
        };
        let raw = match self.files.borrow().insert_raw_fd(guest) {
            Ok(raw) => raw,
            Err(guest) => {
                let _ = self.global.close_linux_pipe(&guest);
                let _ = self.global.close_linux_pipe(&host);
                return Err(Errno::EMFILE);
            }
        };
        Ok((
            raw.try_into().expect("guest descriptor fits u32"),
            Endpoint {
                global: self.global.clone(),
                fd: host,
                wait: WaitState::new(self.global.platform),
            },
        ))
    }

    fn attach_host_input(&self) -> Result<(u32, HostWriter<P>), Errno> {
        self.attach_host_pipe(true)
            .map(|(fd, end)| (fd, HostWriter(end)))
    }

    fn attach_host_output(&self) -> Result<(u32, HostReader<P>), Errno> {
        self.attach_host_pipe(false)
            .map(|(fd, end)| (fd, HostReader(end)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::init_platform;

    #[test]
    fn host_pipe_round_trip_and_eof() {
        let task = init_platform(None);
        let (input, mut writer) = task.attach_host_input().unwrap();
        let (output, mut reader) = task.attach_host_output().unwrap();
        assert_ne!(input, output);
        assert_eq!(writer.write(b"ping"), Ok(4));
        let mut buf = [0; 8];
        assert_eq!(
            task.sys_read(i32::try_from(input).unwrap(), &mut buf[..2], None),
            Ok(2)
        );
        assert_eq!(&buf[..2], b"pi");
        assert_eq!(
            task.sys_read(i32::try_from(input).unwrap(), &mut buf[..2], None),
            Ok(2)
        );
        assert_eq!(&buf[..2], b"ng");
        assert_eq!(
            task.sys_write(i32::try_from(output).unwrap(), b"pong", None),
            Ok(4)
        );
        assert_eq!(reader.read(&mut buf), Ok(4));
        assert_eq!(&buf[..4], b"pong");
        drop(writer);
        assert_eq!(
            task.sys_read(i32::try_from(input).unwrap(), &mut buf, None),
            Ok(0)
        );
        task.sys_close(i32::try_from(output).unwrap()).unwrap();
        assert_eq!(reader.read(&mut buf), Ok(0));
        task.sys_close(i32::try_from(input).unwrap()).unwrap();
    }

    #[test]
    fn host_pipe_peer_close_rejects_writes() {
        let task = init_platform(None);
        let (input, mut writer) = task.attach_host_input().unwrap();
        task.sys_close(i32::try_from(input).unwrap()).unwrap();
        assert_eq!(writer.write(b"x"), Err(Errno::EPIPE));
        let (output, reader) = task.attach_host_output().unwrap();
        drop(reader);
        assert_eq!(
            task.sys_write(i32::try_from(output).unwrap(), b"x", None),
            Err(Errno::EPIPE)
        );
        task.sys_close(i32::try_from(output).unwrap()).unwrap();
    }

    #[test]
    fn host_pipe_respects_descriptor_limit() {
        let task = init_platform(None);
        task.files.borrow().set_max_fd(0);
        assert!(matches!(task.attach_host_input(), Err(Errno::EMFILE)));
        assert!(matches!(task.attach_host_output(), Err(Errno::EMFILE)));
        task.files.borrow().set_max_fd(16);
        let (fd, writer) = task.attach_host_input().unwrap();
        task.sys_close(i32::try_from(fd).unwrap()).unwrap();
        drop(writer);
    }
}
