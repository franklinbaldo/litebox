// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};

use litebox_broker_protocol::wire::WireError;
use litebox_broker_transport::control_ring::ControlRingError;

const MAX_FRAME_LEN: usize = 64 * 1024;

pub(crate) fn read_frame(stream: &mut impl Read) -> IoResult<Option<Vec<u8>>> {
    let mut length = [0; 4];
    let mut completed = 0;
    while completed < length.len() {
        match stream.read(&mut length[completed..]) {
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
        match stream.read(&mut frame[completed..]) {
            Ok(0) => return Err(invalid_data("truncated broker frame")),
            Ok(read) => completed += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Some(frame))
}

pub(crate) fn write_frame(stream: &mut impl Write, frame: &[u8]) -> IoResult<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let length = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(frame)
}

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
        write_frame(&mut bytes, b"frame").unwrap();
        assert_eq!(
            read_frame(&mut bytes.as_slice()).unwrap(),
            Some(b"frame".to_vec())
        );
    }
}
