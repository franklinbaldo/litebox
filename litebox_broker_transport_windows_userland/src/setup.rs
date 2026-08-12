// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::sync::mpsc::{RecvTimeoutError, TryRecvError, channel};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::wire::WireError;
use litebox_broker_transport::control_ring::ControlRingError;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

const MAX_FRAME_LEN: usize = 64 * 1024;

pub(crate) struct OwnedThreadHandle(pub(crate) HANDLE);

pub(crate) fn read_frame(
    stream: &mut impl Read,
    deadline: Option<Instant>,
) -> IoResult<Option<Vec<u8>>> {
    let mut length = [0; 4];
    let mut completed = 0;
    while completed < length.len() {
        match with_io_deadline(deadline, || stream.read(&mut length[completed..])) {
            Ok(0) if completed == 0 => return Ok(None),
            Ok(0) => return Err(invalid_data("truncated broker frame length")),
            Ok(read) => completed += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let mut frame = vec![0; length];
    let mut completed = 0;
    while completed < frame.len() {
        match with_io_deadline(deadline, || stream.read(&mut frame[completed..])) {
            Ok(0) => return Err(invalid_data("truncated broker frame")),
            Ok(read) => completed += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Some(frame))
}

pub(crate) fn write_frame(
    stream: &mut impl Write,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let length = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
    write_all_with_deadline(stream, &length.to_le_bytes(), deadline)?;
    write_all_with_deadline(stream, frame, deadline)
}

fn write_all_with_deadline(
    stream: &mut impl Write,
    mut bytes: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    while !bytes.is_empty() {
        match with_io_deadline(deadline, || stream.write(bytes)) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to write broker frame",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn with_io_deadline<T>(
    deadline: Option<Instant>,
    operation: impl FnOnce() -> IoResult<T>,
) -> IoResult<T> {
    let Some(deadline) = deadline else {
        return operation();
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::new(
            ErrorKind::TimedOut,
            "broker setup deadline elapsed",
        ));
    }

    let io_thread = duplicate_current_thread()?;
    let (completed, wait_for_completion) = channel();
    let watchdog = thread::Builder::new()
        .name("litebox-setup-deadline".to_owned())
        .spawn(move || match wait_for_completion.recv_timeout(remaining) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => Ok::<bool, Error>(false),
            Err(RecvTimeoutError::Timeout) => loop {
                if io_thread.cancel_synchronous_io()? {
                    return Ok(true);
                }
                match wait_for_completion.try_recv() {
                    Ok(()) | Err(TryRecvError::Disconnected) => return Ok(true),
                    Err(TryRecvError::Empty) => thread::yield_now(),
                }
            },
        })?;
    let result = operation();
    let _ = completed.send(());
    let timed_out = watchdog
        .join()
        .map_err(|_| Error::other("broker setup deadline watchdog panicked"))??;
    if timed_out {
        Err(Error::new(
            ErrorKind::TimedOut,
            "broker setup deadline elapsed",
        ))
    } else {
        result
    }
}

pub(crate) fn duplicate_current_thread() -> IoResult<OwnedThreadHandle> {
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: Both process pseudo-handles and the current-thread pseudo-handle are valid, and the
    // output points to writable storage for a new real thread handle.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(Error::last_os_error());
    }
    Ok(OwnedThreadHandle(duplicate))
}

impl OwnedThreadHandle {
    fn cancel_synchronous_io(&self) -> IoResult<bool> {
        // SAFETY: This is a live duplicate of the thread performing synchronous I/O.
        if unsafe { CancelSynchronousIo(self.0) } == 0 {
            let error = Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(true)
    }
}

impl Drop for OwnedThreadHandle {
    fn drop(&mut self) {
        // SAFETY: This is a live thread handle returned by DuplicateHandle.
        unsafe { CloseHandle(self.0) };
    }
}

// SAFETY: Windows thread handles can be canceled and closed from any process thread.
unsafe impl Send for OwnedThreadHandle {}

pub(crate) fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

pub(crate) fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

pub(crate) fn copy_io_error(error: &Error) -> Error {
    match error.raw_os_error() {
        Some(code) => Error::from_raw_os_error(code),
        None => Error::new(error.kind(), error.to_string()),
    }
}

pub(crate) fn ring_error(error: ControlRingError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker control ring: {error:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"frame", None).unwrap();
        assert_eq!(
            read_frame(&mut bytes.as_slice(), None).unwrap(),
            Some(b"frame".to_vec())
        );
    }
}
