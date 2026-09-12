// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

use std::io::{self, Read};

pub const WIDTH: usize = 160;
pub const HEIGHT: usize = 120;
pub const SAMPLES: usize = 735;

#[derive(Debug, PartialEq)]
pub enum Packet {
    Frame,
    Audio,
}

/// Decode one bounded demo packet into reusable buffers. EOF is only clean
/// between packets; a partial header or body is a protocol error.
pub fn read_packet(
    reader: &mut impl Read,
    frame: &mut [u8; WIDTH * HEIGHT * 3],
    audio: &mut [u8; SAMPLES * 2],
) -> io::Result<Option<Packet>> {
    let mut tag = [0; 4];
    loop {
        match reader.read(&mut tag[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    reader.read_exact(&mut tag[1..])?;
    match &tag {
        b"FRAM" => {
            let mut dimensions = [0; 4];
            reader.read_exact(&mut dimensions)?;
            if usize::from(u16::from_le_bytes([dimensions[0], dimensions[1]])) != WIDTH
                || usize::from(u16::from_le_bytes([dimensions[2], dimensions[3]])) != HEIGHT
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid frame dimensions",
                ));
            }
            reader.read_exact(frame)?;
            Ok(Some(Packet::Frame))
        }
        b"SND0" => {
            let mut count = [0; 2];
            reader.read_exact(&mut count)?;
            if usize::from(u16::from_le_bytes(count)) != SAMPLES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid audio length",
                ));
            }
            reader.read_exact(audio)?;
            Ok(Some(Packet::Audio))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown packet tag",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> io::Result<Option<Packet>> {
        read_packet(
            &mut &*bytes,
            &mut [0; WIDTH * HEIGHT * 3],
            &mut [0; SAMPLES * 2],
        )
    }

    #[test]
    fn clean_eof_differs_from_truncation() {
        assert_eq!(decode(b"").unwrap(), None);
        for bytes in [
            b"F".as_slice(),
            b"FRAM",
            b"FRAM\xa0\0\x78\0",
            b"SND0\xdf\x02",
        ] {
            assert_eq!(
                decode(bytes).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[test]
    fn invalid_lengths_and_tags_rejected_before_body_read() {
        for bytes in [b"FRAM\xff\xff\xff\xff".as_slice(), b"SND0\xff\xff", b"NOPE"] {
            assert_eq!(
                decode(bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn fragmented_packets_reuse_bounded_buffers() {
        struct Fragmented(io::Cursor<Vec<u8>>);
        impl Read for Fragmented {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let length = out.len().min(3);
                self.0.read(&mut out[..length])
            }
        }
        let mut bytes = b"FRAM\xa0\0\x78\0".to_vec();
        bytes.extend(vec![17; WIDTH * HEIGHT * 3]);
        bytes.extend(b"SND0\xdf\x02");
        bytes.extend(vec![23; SAMPLES * 2]);
        let mut stream = Fragmented(io::Cursor::new(bytes));
        let mut frame = [0; WIDTH * HEIGHT * 3];
        let mut audio = [0; SAMPLES * 2];
        assert_eq!(
            read_packet(&mut stream, &mut frame, &mut audio).unwrap(),
            Some(Packet::Frame)
        );
        assert!(frame.iter().all(|b| *b == 17));
        assert_eq!(
            read_packet(&mut stream, &mut frame, &mut audio).unwrap(),
            Some(Packet::Audio)
        );
        assert!(audio.iter().all(|b| *b == 23));
        assert_eq!(
            read_packet(&mut stream, &mut frame, &mut audio).unwrap(),
            None
        );
    }
}
