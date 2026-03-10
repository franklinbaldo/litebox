// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Device provider for LiteBox including:
//! 1. Standard input/output devices.
//! 2. /dev/null device.
//! 3. Pseudo-terminal (PTY) devices (/dev/ptmx, /dev/pts/*).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use alloc::sync::Weak;

use crate::{
    LiteBox,
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    fs::{
        FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
        errors::{
            ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
            ReadDirError, ReadError, RenameError, RmdirError, SeekError, TruncateError,
            UnlinkError, WriteError,
        },
    },
    path::Arg,
    platform::{StdioOutStream, StdioReadError, StdioWriteError, TimeProvider},
};

/// Block size for stdio devices
const STDIO_BLOCK_SIZE: usize = 1024;
/// Block size for null device
const NULL_BLOCK_SIZE: usize = 0x1000;
/// Block size for /dev/urandom
const URANDOM_BLOCK_SIZE: usize = 0x1000;

/// Constant node information for all 3 stdio devices.
///
/// We use rdev major=5, minor=0 (same as `/dev/tty` on Linux) rather than a
/// PTY-slave rdev (major=136) to prevent callers from mistakenly treating
/// the stdio stream as a PTY master (e.g., `TIOCGPTN` should fail on these).
const STDIO_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 9,
    // major=5, minor=0 — matches /dev/tty (character device, terminal).
    // The runner's stdin/stdout/stderr are typically PTY slave FDs inherited
    // from the host shell, so reporting them as a terminal is correct.
    rdev: core::num::NonZeroUsize::new(0x500),
};
/// Node info for /dev/null
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    // major=1, minor=3
    rdev: core::num::NonZeroUsize::new(0x103),
};
/// Node info for /dev/urandom
const URANDOM_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 8,
    // major=1, minor=9
    rdev: core::num::NonZeroUsize::new(0x109),
};
/// Node info for /dev/ptmx
const PTMX_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 2,
    // major=5, minor=2
    rdev: core::num::NonZeroUsize::new(0x502),
};

/// Stored terminal attributes for a PTY pair.
///
/// These are the raw flag values from the Linux `struct termios`.
/// The line discipline in master/slave write checks these flags
/// to decide whether to apply ECHO, ICRNL, ONLCR, etc.
#[derive(Debug, Clone)]
pub struct PtyTermios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_cc: [u8; 19],
}

// Linux termios flag constants used by the PTY line discipline.
const ECHO: u32 = 0x0008;
const ICRNL: u32 = 0x0100;
const OPOST: u32 = 0x0001;
const ONLCR: u32 = 0x0004;

impl PtyTermios {
    /// Default PTY termios matching a freshly opened Linux PTY.
    fn new() -> Self {
        Self {
            c_iflag: 0x6d02, // ICRNL | IXON | IXANY | IMAXBEL | IUTF8
            c_oflag: 0x0005, // OPOST | ONLCR
            c_cflag: 0x04bf, // CS8 | CREAD | CLOCAL | B38400
            c_lflag: 0x8a3b, // ECHO | ECHOE | ECHOK | ISIG | ICANON | IEXTEN | ECHOCTL | ECHOKE
            c_cc: [
                0x03, 0x1c, 0x7f, 0x15, 0x04, 0x00, 0x01, 0x00, 0x11, 0x13, 0x1a, 0xff, 0x12, 0x0f,
                0x17, 0x16, 0xff, 0x00, 0x00,
            ],
        }
    }

    pub fn echo_enabled(&self) -> bool {
        self.c_lflag & ECHO != 0
    }

    pub fn icrnl_enabled(&self) -> bool {
        self.c_iflag & ICRNL != 0
    }

    pub fn onlcr_enabled(&self) -> bool {
        (self.c_oflag & OPOST != 0) && (self.c_oflag & ONLCR != 0)
    }
}

/// Shared state for a single PTY pair (master ↔ slave).
pub struct PtyPair<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider> {
    /// Data written to master, read by slave (input to the child process).
    pub master_to_slave: crate::sync::Mutex<Platform, VecDeque<u8>>,
    /// Data written to slave, read by master (output from the child process).
    pub slave_to_master: crate::sync::Mutex<Platform, VecDeque<u8>>,
    /// Whether the slave side has been unlocked via TIOCSPTLK.
    pub unlocked: core::sync::atomic::AtomicBool,
    /// Whether the slave side is open (used for EOF detection).
    pub slave_open: core::sync::atomic::AtomicBool,
    /// Whether the master side is open (used for EIO on slave reads).
    pub master_open: core::sync::atomic::AtomicBool,
    /// Pollee for notifying epoll when data is available for master reads.
    pub master_pollee: Pollee<Platform>,
    /// Pollee for notifying poll/select when data is available for slave reads.
    pub slave_pollee: Pollee<Platform>,
    /// Stored terminal attributes — modified by TCSETS, read by TCGETS.
    pub termios: crate::sync::Mutex<Platform, PtyTermios>,
}

/// Wrapper for polling the master side of a PTY pair.
///
/// Implements `IOPollable` so that epoll can monitor the PTY master fd
/// for readability (data written by slave) and writability.
pub struct PtyMasterPollable<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider>(
    pub Arc<PtyPair<Platform>>,
);

impl<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider> IOPollable
    for PtyMasterPollable<Platform>
{
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.0.master_pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::OUT; // master is always writable
        if !self.0.slave_to_master.lock().is_empty() {
            events |= Events::IN;
        }
        if !self
            .0
            .slave_open
            .load(core::sync::atomic::Ordering::Acquire)
        {
            events |= Events::HUP;
        }
        events
    }

    fn should_block_read(&self) -> bool {
        false
    }
}

/// Wrapper for polling the slave side of a PTY pair.
///
/// Implements `IOPollable` so that poll/select can monitor the PTY slave fd
/// for readability (data written by master) and writability.
pub struct PtySlavePollable<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider>(
    pub Arc<PtyPair<Platform>>,
);

impl<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider> IOPollable
    for PtySlavePollable<Platform>
{
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.0.slave_pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::OUT; // slave is always writable
        if !self.0.master_to_slave.lock().is_empty() {
            events |= Events::IN;
        }
        if !self
            .0
            .master_open
            .load(core::sync::atomic::Ordering::Acquire)
        {
            events |= Events::HUP;
        }
        events
    }
}

/// Wrapper for polling host stdin.
///
/// Implements `IOPollable` by querying the host kernel to check if stdin has
/// data available. This enables epoll/poll/select on the guest's stdin fd.
pub struct StdinPollable(pub Arc<dyn Fn() -> bool + Send + Sync>);

impl IOPollable for StdinPollable {
    fn register_observer(&self, _observer: Weak<dyn Observer<Events>>, _mask: Events) {
        // Stdin observers are not cached — check_io_events polls the host each
        // time. The epoll wait loop calls scan_once repeatedly with short
        // timeouts, so this effectively acts as level-triggered polling.
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::OUT;
        if (self.0)() {
            events |= Events::IN;
        }
        events
    }

    fn needs_host_poll(&self) -> bool {
        true
    }
}

/// Manages all allocated PTY pairs.
pub struct PtyManager<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider> {
    pairs: crate::sync::Mutex<Platform, Vec<Arc<PtyPair<Platform>>>>,
}

impl<Platform: crate::sync::RawSyncPrimitivesProvider + TimeProvider> PtyManager<Platform> {
    fn new() -> Self {
        Self {
            pairs: crate::sync::Mutex::new(Vec::new()),
        }
    }

    /// Allocate a new PTY pair, returning its index.
    fn alloc(&self) -> u32 {
        let mut pairs = self.pairs.lock();
        let idx = u32::try_from(pairs.len()).expect("PTY index overflow");
        pairs.push(Arc::new(PtyPair {
            master_to_slave: crate::sync::Mutex::new(VecDeque::new()),
            slave_to_master: crate::sync::Mutex::new(VecDeque::new()),
            unlocked: true.into(),
            slave_open: false.into(),
            master_open: true.into(),
            master_pollee: Pollee::new(),
            slave_pollee: Pollee::new(),
            termios: crate::sync::Mutex::new(PtyTermios::new()),
        }));
        idx
    }

    /// Get the PTY pair at `idx`.
    pub fn get(&self, idx: u32) -> Option<Arc<PtyPair<Platform>>> {
        self.pairs.lock().get(idx as usize).cloned()
    }
}

#[derive(Debug, Clone, Copy)]
enum Device {
    Stdin,
    Stdout,
    Stderr,
    Null,
    URandom,
    /// Master side of PTY pair (index into PtyManager).
    PtyMaster(u32),
    /// Slave side of PTY pair (index into PtyManager).
    PtySlave(u32),
}

/// A backing implementation for [`FileSystem`](super::FileSystem).
///
/// This provider provides `/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
/// `/dev/null`, `/dev/urandom`, and pseudo-terminal devices (`/dev/ptmx`,
/// `/dev/pts/*`).
pub struct FileSystem<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + TimeProvider
        + 'static,
> {
    litebox: LiteBox<Platform>,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    pty_manager: PtyManager<Platform>,
}

impl<
    Platform: crate::platform::StdioProvider + crate::sync::RawSyncPrimitivesProvider + TimeProvider,
> FileSystem<Platform>
{
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            litebox: litebox.clone(),
            current_working_dir: "/".into(),
            pty_manager: PtyManager::new(),
        }
    }

    /// Get the PTY pair for a PTY device FD.
    ///
    /// Returns `(pair, pty_number, is_master)` if the FD refers to a PTY device.
    pub fn get_pty_info(
        &self,
        fd: &FileFd<Platform>,
    ) -> Option<(Arc<PtyPair<Platform>>, u32, bool)> {
        let table = self.litebox.descriptor_table();
        let entry = table.get_entry(fd)?;
        match entry.entry {
            Device::PtyMaster(idx) => {
                let pair = self.pty_manager.get(idx)?;
                Some((pair, idx, true))
            }
            Device::PtySlave(idx) => {
                let pair = self.pty_manager.get(idx)?;
                Some((pair, idx, false))
            }
            _ => None,
        }
    }
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + TimeProvider,
> super::private::Sealed for FileSystem<Platform>
{
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + TimeProvider,
> FileSystem<Platform>
{
    // Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    // for any relative paths from current working directory.
    //
    // Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            // Absolute path
            Ok(path.normalized()?)
        } else {
            // Relative path
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }

    fn device_file_status(device: Device) -> FileStatus {
        match device {
            Device::Stdin | Device::Stdout | Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIO_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: URANDOM_NODE_INFO,
                blksize: URANDOM_BLOCK_SIZE,
            },
            Device::PtyMaster(n) | Device::PtySlave(n) => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NodeInfo {
                    dev: 5,
                    // major=136, minor=n (Linux pts convention)
                    ino: (n + 3) as usize,
                    rdev: core::num::NonZeroUsize::new(0x8800 + n as usize),
                },
                blksize: STDIO_BLOCK_SIZE,
            },
        }
    }

    /// Returns the PTY pair index if the given FD is a PTY master, or `None` otherwise.
    pub fn get_pty_master_index(&self, fd: &FileFd<Platform>) -> Option<u32> {
        let table = self.litebox.descriptor_table();
        match table.get_entry(fd)?.entry {
            Device::PtyMaster(idx) => Some(idx),
            _ => None,
        }
    }

    /// Returns a reference to the PTY manager for performing PTY operations.
    pub fn pty_manager(&self) -> &PtyManager<Platform> {
        &self.pty_manager
    }
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + TimeProvider,
> super::FileSystem for FileSystem<Platform>
{
    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let open_directory = flags.contains(OFlags::DIRECTORY);
        let flags = flags - OFlags::DIRECTORY;
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let flags = flags - OFlags::NONBLOCK;
        // ignore NOCTTY, NOFOLLOW, and APPEND
        let flags = flags - OFlags::NOCTTY - OFlags::NOFOLLOW - OFlags::APPEND;
        let truncate = flags.contains(OFlags::TRUNC);
        let flags = flags - OFlags::TRUNC;
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => {
                if flags == OFlags::RDONLY && mode.is_empty() {
                    Device::Stdin
                } else {
                    unimplemented!()
                }
            }
            "/dev/stdout" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Device::Stdout
                } else {
                    unimplemented!()
                }
            }
            "/dev/stderr" => {
                if flags == OFlags::WRONLY && mode.is_empty() {
                    Device::Stderr
                } else {
                    unimplemented!()
                }
            }
            "/dev/null" => Device::Null,
            "/dev/urandom" => Device::URandom,
            "/dev/ptmx" => {
                let idx = self.pty_manager.alloc();
                Device::PtyMaster(idx)
            }
            p if p.starts_with("/dev/pts/") => {
                let num_str = &p["/dev/pts/".len()..];
                let idx: u32 = num_str
                    .parse()
                    .map_err(|_| OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
                let pair = self
                    .pty_manager
                    .get(idx)
                    .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
                if !pair.unlocked.load(core::sync::atomic::Ordering::Acquire) {
                    return Err(OpenError::AccessNotAllowed);
                }
                pair.slave_open
                    .store(true, core::sync::atomic::Ordering::Release);
                Device::PtySlave(idx)
            }
            _ => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        if open_directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        if nonblocking
            && matches!(
                device,
                Device::Stdin | Device::Stderr | Device::Stdout | Device::URandom
            )
        {
            unimplemented!("Non-blocking I/O is not supported for {:?}", device);
        }
        let fd = self.litebox.descriptor_table_mut().insert(device);
        if truncate {
            // Note: matching Linux behavior, this does not actually perform any truncation, and
            // instead, it is silently ignored if you attempt to truncate upon opening stdio.
            assert!(matches!(
                self.truncate(&fd, 0, true),
                Err(TruncateError::IsTerminalDevice)
            ));
        }
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
        if let Some(entry) = self.litebox.descriptor_table().get_entry(fd) {
            match entry.entry {
                Device::PtyMaster(idx) => {
                    if let Some(pair) = self.pty_manager.get(idx) {
                        pair.master_open
                            .store(false, core::sync::atomic::Ordering::Release);
                    }
                }
                Device::PtySlave(idx) => {
                    if let Some(pair) = self.pty_manager.get(idx) {
                        pair.slave_open
                            .store(false, core::sync::atomic::Ordering::Release);
                    }
                }
                _ => {}
            }
        }
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        _offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        {
            Device::Stdin => {}
            Device::Stdout | Device::Stderr => {
                return Err(ReadError::NotForReading);
            }
            Device::Null => {
                // /dev/null read returns EOF
                return Ok(0);
            }
            Device::URandom => {
                self.litebox.x.platform.fill_bytes_crng(buf);
                return Ok(buf.len());
            }
            &Device::PtyMaster(idx) => {
                // Master reads what the slave has written
                let pair = self.pty_manager.get(idx).ok_or(ReadError::ClosedFd)?;
                let mut ring = pair.slave_to_master.lock();
                if ring.is_empty() {
                    if !pair.slave_open.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(0); // EOF — slave closed
                    }
                    return Err(ReadError::WouldBlock);
                }
                let n = core::cmp::min(buf.len(), ring.len());
                for (i, byte) in ring.drain(..n).enumerate() {
                    buf[i] = byte;
                }
                return Ok(n);
            }
            &Device::PtySlave(idx) => {
                // Slave reads what the master has written.
                // Returns WouldBlock (EAGAIN) when no data is available;
                // the shim layer handles blocking retry with interruptibility.
                let pair = self.pty_manager.get(idx).ok_or(ReadError::ClosedFd)?;
                let mut ring = pair.master_to_slave.lock();
                if ring.is_empty() {
                    if !pair.master_open.load(core::sync::atomic::Ordering::Acquire) {
                        return Ok(0); // EOF — master closed
                    }
                    return Err(ReadError::WouldBlock);
                }
                let n = core::cmp::min(buf.len(), ring.len());
                for (i, byte) in ring.drain(..n).enumerate() {
                    buf[i] = byte;
                }
                return Ok(n);
            }
        }
        // Stdin is a stream device — offsets are meaningless. Ignore any
        // explicit offset (the layered FS may supply one for concurrency safety).
        self.litebox
            .x
            .platform
            .read_from_stdin(buf)
            .map_err(|e| match e {
                StdioReadError::Closed => unimplemented!(),
            })
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        _offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let stream = match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        {
            Device::Stdin => return Err(WriteError::NotForWriting),
            Device::Stdout => StdioOutStream::Stdout,
            Device::Stderr => StdioOutStream::Stderr,
            Device::Null | Device::URandom => {
                // /dev/null discards data: report as if written fully
                //
                // Writing to /dev/random or /dev/urandom will update the entropy
                // pool with the data written, but this will not result in a higher
                // entropy count. This means that it will impact the contents read
                // from both files, but it will not make reads from /dev/random
                // faster. For simplicity, we just discard the data written to
                // /dev/urandom here.
                return Ok(buf.len());
            }
            &Device::PtyMaster(idx) => {
                // Master writes feed the slave's input buffer.
                // Line discipline: ICRNL translates \r → \n (if enabled).
                // ECHO reflects input back to master's read buffer.
                let pair = self.pty_manager.get(idx).ok_or(WriteError::ClosedFd)?;
                let termios = pair.termios.lock();
                let icrnl = termios.icrnl_enabled();
                let echo = termios.echo_enabled();
                let onlcr = termios.onlcr_enabled();
                drop(termios);
                {
                    let mut slave_ring = pair.master_to_slave.lock();
                    if echo {
                        let mut master_ring = pair.slave_to_master.lock();
                        for &b in buf {
                            let translated = if icrnl && b == b'\r' { b'\n' } else { b };
                            slave_ring.push_back(translated);
                            // Echo: reflect to master read, applying ONLCR.
                            if onlcr && translated == b'\n' {
                                master_ring.push_back(b'\r');
                            }
                            master_ring.push_back(translated);
                        }
                    } else {
                        for &b in buf {
                            slave_ring.push_back(if icrnl && b == b'\r' { b'\n' } else { b });
                        }
                    }
                }
                pair.slave_pollee.notify_observers(Events::IN);
                if echo {
                    pair.master_pollee.notify_observers(Events::IN);
                }
                return Ok(buf.len());
            }
            &Device::PtySlave(idx) => {
                // Slave writes feed the master's read buffer.
                // Line discipline: ONLCR translates \n → \r\n (if enabled).
                let pair = self.pty_manager.get(idx).ok_or(WriteError::ClosedFd)?;
                let onlcr = pair.termios.lock().onlcr_enabled();
                {
                    let mut ring = pair.slave_to_master.lock();
                    if onlcr {
                        for &b in buf {
                            if b == b'\n' {
                                ring.push_back(b'\r');
                            }
                            ring.push_back(b);
                        }
                    } else {
                        for &b in buf {
                            ring.push_back(b);
                        }
                    }
                }
                // Wake epoll watchers on the master side.
                pair.master_pollee.notify_observers(Events::IN);
                return Ok(buf.len());
            }
        };
        // Stdout/stderr are stream devices — offsets are meaningless.
        self.litebox
            .x
            .platform
            .write_to(stream, buf)
            .map_err(|e| match e {
                StdioWriteError::Closed => unimplemented!(),
            })
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        _offset: isize,
        _whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        {
            Device::Stdin
            | Device::Stdout
            | Device::Stderr
            | Device::PtyMaster(_)
            | Device::PtySlave(_) => Err(SeekError::NonSeekable),
            Device::Null | Device::URandom => {
                // Linux allows lseek on /dev/null and returns position 0 (or sets to length 0).
                Ok(0)
            }
        }
    }

    fn truncate(
        &self,
        _fd: &FileFd<Platform>,
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        unimplemented!()
    }

    fn rename(&self, _old: impl Arg, _new: impl Arg) -> Result<(), RenameError> {
        unimplemented!()
    }

    #[expect(unused_variables, reason = "not supported by device filesystem")]
    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        Err(MkdirError::Io)
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        unimplemented!()
    }

    fn read_dir(
        &self,
        _fd: &FileFd<Platform>,
    ) -> Result<alloc::vec::Vec<crate::fs::DirEntry>, ReadDirError> {
        Err(ReadDirError::NotADirectory)
    }

    fn file_status(&self, path: impl Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => Device::Stdin,
            "/dev/stdout" => Device::Stdout,
            "/dev/stderr" => Device::Stderr,
            "/dev/null" => Device::Null,
            "/dev/urandom" => Device::URandom,
            "/dev/ptmx" => {
                return Ok(FileStatus {
                    file_type: FileType::CharacterDevice,
                    mode: Mode::RUSR
                        | Mode::WUSR
                        | Mode::RGRP
                        | Mode::WGRP
                        | Mode::ROTH
                        | Mode::WOTH,
                    size: 0,
                    owner: UserInfo::ROOT,
                    node_info: PTMX_NODE_INFO,
                    blksize: STDIO_BLOCK_SIZE,
                });
            }
            p if p.starts_with("/dev/pts/") => {
                let num_str = &p["/dev/pts/".len()..];
                let idx: u32 = num_str
                    .parse()
                    .map_err(|_| FileStatusError::PathError(PathError::NoSuchFileOrDirectory))?;
                if self.pty_manager.get(idx).is_some() {
                    return Ok(Self::device_file_status(Device::PtySlave(idx)));
                }
                return Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory));
            }
            "/dev" | "/dev/" | "/dev/pts" | "/dev/pts/" => {
                return Ok(FileStatus {
                    file_type: FileType::Directory,
                    mode: Mode::RUSR
                        | Mode::XUSR
                        | Mode::RGRP
                        | Mode::XGRP
                        | Mode::ROTH
                        | Mode::XOTH,
                    size: 0,
                    owner: UserInfo::ROOT,
                    node_info: NodeInfo {
                        dev: 5,
                        ino: 1,
                        rdev: None,
                    },
                    blksize: 4096,
                });
            }
            _ => return Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        Ok(Self::device_file_status(device))
    }

    fn fd_file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let device = self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(FileStatusError::ClosedFd)?
            .entry;
        Ok(Self::device_file_status(device))
    }

    fn get_io_pollable(
        &self,
        fd: &FileFd<Platform>,
    ) -> Option<alloc::boxed::Box<dyn crate::event::IOPollable>> {
        let table = self.litebox.descriptor_table();
        let entry = table.get_entry(fd)?;
        match entry.entry {
            Device::Stdin => {
                let litebox = self.litebox.clone();
                Some(alloc::boxed::Box::new(StdinPollable(Arc::new(move || {
                    litebox.x.platform.poll_stdin_readable()
                }))))
            }
            Device::PtyMaster(idx) => {
                let pair = self.pty_manager.get(idx)?;
                Some(alloc::boxed::Box::new(PtyMasterPollable(pair)))
            }
            Device::PtySlave(idx) => {
                let pair = self.pty_manager.get(idx)?;
                Some(alloc::boxed::Box::new(PtySlavePollable(pair)))
            }
            _ => None,
        }
    }

    fn get_pty_termios(&self, fd: &FileFd<Platform>) -> Option<PtyTermios> {
        let (pair, _, _) = self.get_pty_info(fd)?;
        Some(pair.termios.lock().clone())
    }

    fn set_pty_termios(&self, fd: &FileFd<Platform>, termios: PtyTermios) -> bool {
        if let Some((pair, _, _)) = self.get_pty_info(fd) {
            *pair.termios.lock() = termios;
            true
        } else {
            false
        }
    }
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + crate::platform::TimeProvider };
    FileSystem<Platform>;
    Device;
    -> FileFd<Platform>;
}
