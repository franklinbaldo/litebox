//! Bounded integration fixture: real SDL Linux guest -> dedicated pipes -> WinMM Windows.

use std::io;
use std::time::Duration;

use litebox_desktop_host::audio::WinMMAudio;
use litebox_platform_windows_userland::WindowsUserland;
use litebox_shim_linux::host_pipe::{HostReader, HostWriter};

pub const AUD0_MAGIC: [u8; 4] = *b"AUD0";
pub const ACK0_PAYLOAD: [u8; 4] = *b"ACK0";
pub const EXPECTED_RATE: u32 = 22050;
pub const EXPECTED_CHANNELS: u16 = 1;
pub const EXPECTED_BITS: u16 = 16;
pub const MAX_PCM_BYTES: usize = 2048;

struct Reader(HostReader<WindowsUserland>);
impl io::Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .read(buf)
            .map_err(|e| io::Error::other(format!("{e:?}")))
    }
}

struct Writer(HostWriter<WindowsUserland>);
impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .write(buf)
            .map_err(|e| io::Error::other(format!("{e:?}")))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AudioPacket {
    pub rate: u32,
    pub channels: u16,
    pub bits: u16,
    pub pcm: Vec<u8>,
}

pub fn parse_audio_frame(body: &[u8]) -> anyhow::Result<AudioPacket> {
    anyhow::ensure!(
        body.len() >= 16,
        "audio frame header too short: {} bytes (minimum 16)",
        body.len()
    );
    anyhow::ensure!(body[..4] == AUD0_MAGIC, "invalid audio frame magic tag");
    let rate = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    anyhow::ensure!(
        rate == EXPECTED_RATE,
        "unsupported sample rate: {rate} (expected {EXPECTED_RATE})"
    );
    let channels = u16::from_le_bytes([body[8], body[9]]);
    anyhow::ensure!(
        channels == EXPECTED_CHANNELS,
        "unsupported channels: {channels} (expected {EXPECTED_CHANNELS})"
    );
    let bits = u16::from_le_bytes([body[10], body[11]]);
    anyhow::ensure!(
        bits == EXPECTED_BITS,
        "unsupported bits per sample: {bits} (expected {EXPECTED_BITS})"
    );
    let pcm_len = u32::from_le_bytes([body[12], body[13], body[14], body[15]]) as usize;
    anyhow::ensure!(pcm_len > 0, "pcm length cannot be 0");
    anyhow::ensure!(
        pcm_len.is_multiple_of(2),
        "pcm length must be even: {pcm_len}"
    );
    anyhow::ensure!(
        pcm_len <= MAX_PCM_BYTES,
        "pcm length {pcm_len} exceeds limit {MAX_PCM_BYTES}"
    );
    anyhow::ensure!(
        body.len() == 16 + pcm_len,
        "exact length mismatch: body.len() is {}, expected {}",
        body.len(),
        16 + pcm_len
    );
    Ok(AudioPacket {
        rate,
        channels,
        bits,
        pcm: body[16..].to_vec(),
    })
}

#[derive(Clone, Debug, Default)]
pub struct AudioStats {
    pub received: usize,
    pub submitted: usize,
    pub completed: usize,
    pub canceled: usize,
    pub non_silent: usize,
    pub errors: usize,
    pub min_sample: i16,
    pub max_sample: i16,
    pub has_positive: bool,
    pub has_negative: bool,
}

fn main() -> anyhow::Result<()> {
    let tar_path = std::env::args_os()
        .nth(1)
        .expect("audio probe TAR path required as argument 1");

    let platform = WindowsUserland::new();
    let builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let fs = builder.default_fs(
        litebox::fs::in_mem::InMem::new_initialized::<&str>([]),
        std::fs::read(&tar_path)?.into(),
    );
    let shim = builder.build();
    let mut program = shim.load_program(
        std::sync::Arc::new(fs),
        platform.init_task(),
        "/bin/probe",
        vec![std::ffi::CString::new("probe")?],
        vec![std::ffi::CString::new("SDL_AUDIODRIVER=litebox")?],
    )?;

    // Reserve guest descriptors 3/4 for video without using them
    let (v_in, _v_writer) = program.attach_host_input()?;
    let (v_out, _v_reader) = program.attach_host_output()?;

    // Attach input5 / output6 for audio
    let (a_in, a_writer) = program.attach_host_input()?;
    let (a_out, a_reader) = program.attach_host_output()?;

    anyhow::ensure!(
        (v_in, v_out, a_in, a_out) == (3, 4, 5, 6),
        "unexpected fixture descriptors: v_in={v_in}, v_out={v_out}, a_in={a_in}, a_out={a_out}"
    );

    let audio_thread = std::thread::spawn(move || -> anyhow::Result<AudioStats> {
        let mut wire =
            litebox_desktop_transport::Framed::new(Reader(a_reader), Writer(a_writer), 1_048_576)
                .map_err(|e| anyhow::anyhow!("failed to create Framed transport: {e}"))?;

        eprintln!("host: audio handshake waiting");
        wire.handshake(0)
            .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
        eprintln!("host: audio handshake complete");

        let (mut audio_device, ok) = WinMMAudio::open()
            .ok_or_else(|| anyhow::anyhow!("failed to open WinMM waveOut device"))?;
        anyhow::ensure!(ok, "WinMMAudio::open returned ok=false");

        let mut received_count = 0;
        let mut min_sample = i16::MAX;
        let mut max_sample = i16::MIN;
        let mut has_positive = false;
        let mut has_negative = false;

        while let Some(body) = wire
            .recv()
            .map_err(|e| anyhow::anyhow!("recv error: {e}"))?
        {
            received_count += 1;
            let packet = parse_audio_frame(&body)?;

            for chunk in packet.pcm.chunks_exact(2) {
                let s = i16::from_le_bytes([chunk[0], chunk[1]]);
                if s > max_sample {
                    max_sample = s;
                }
                if s < min_sample {
                    min_sample = s;
                }
                if s > 0 {
                    has_positive = true;
                }
                if s < 0 {
                    has_negative = true;
                }
            }

            // Play the buffer and wait for WHDR_DONE before sending ACK0
            audio_device
                .play_and_wait(&packet.pcm, Duration::from_secs(2))
                .map_err(|e| {
                    anyhow::anyhow!("WinMM playback error on buffer {received_count}: {e}")
                })?;

            // Send framed ACK0 only after WHDR_DONE has completed
            wire.send(&ACK0_PAYLOAD)
                .map_err(|e| anyhow::anyhow!("failed to send ACK0: {e}"))?;
        }

        audio_device.close();
        let metrics = audio_device.metrics.clone();

        Ok(AudioStats {
            received: received_count,
            submitted: metrics.submitted,
            completed: metrics.completed,
            canceled: metrics.canceled,
            non_silent: metrics.non_silent,
            errors: metrics.errors.len(),
            min_sample,
            max_sample,
            has_positive,
            has_negative,
        })
    });

    // Run guest thread
    // SAFETY: these entrypoints and registers belong to this loaded guest.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    eprintln!("guest: run_thread returned");
    let exit = program.process.wait();
    eprintln!("guest: exit {exit}");

    let stats = audio_thread.join().expect("audio thread panicked")?;

    anyhow::ensure!(exit == 0, "guest exited with non-zero code {exit}");
    anyhow::ensure!(
        stats.completed >= 8,
        "fewer than 8 buffers completed: {}",
        stats.completed
    );
    anyhow::ensure!(stats.errors == 0, "audio errors occurred: {}", stats.errors);
    anyhow::ensure!(
        stats.received == stats.submitted && stats.submitted == stats.completed,
        "audio buffer counts differ: received={}, submitted={}, completed={}",
        stats.received,
        stats.submitted,
        stats.completed
    );
    anyhow::ensure!(
        stats.canceled == 0,
        "audio buffers canceled: {}",
        stats.canceled
    );
    anyhow::ensure!(stats.has_positive, "no positive PCM samples found");
    anyhow::ensure!(stats.has_negative, "no negative PCM samples found");
    anyhow::ensure!(stats.non_silent > 0, "no non-silent audio buffers");

    println!(
        "SDL_AUDIO_METRICS: received={} submitted={} completed={} canceled={} non_silent={} errors={} min_sample={} max_sample={} has_pos={} has_neg={} guest_exit={exit}",
        stats.received,
        stats.submitted,
        stats.completed,
        stats.canceled,
        stats.non_silent,
        stats.errors,
        stats.min_sample,
        stats.max_sample,
        stats.has_positive,
        stats.has_negative
    );
    println!(
        "SDL_AUDIO_OK: {} verified buffers played via WinMM; guest exit 0",
        stats.completed
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_packet(pcm_bytes: usize) -> Vec<u8> {
        let mut body = vec![0u8; 16 + pcm_bytes];
        body[..4].copy_from_slice(&AUD0_MAGIC);
        body[4..8].copy_from_slice(&EXPECTED_RATE.to_le_bytes());
        body[8..10].copy_from_slice(&EXPECTED_CHANNELS.to_le_bytes());
        body[10..12].copy_from_slice(&EXPECTED_BITS.to_le_bytes());
        body[12..16].copy_from_slice(&(pcm_bytes as u32).to_le_bytes());
        for i in 0..pcm_bytes / 2 {
            let sample: i16 = if i % 2 == 0 { 4000 } else { -4000 };
            body[16 + i * 2..16 + (i + 1) * 2].copy_from_slice(&sample.to_le_bytes());
        }
        body
    }

    #[test]
    fn parse_valid_audio_frame() {
        let body = build_valid_packet(1024);
        let parsed = parse_audio_frame(&body).expect("should parse valid frame");
        assert_eq!(parsed.rate, 22050);
        assert_eq!(parsed.channels, 1);
        assert_eq!(parsed.bits, 16);
        assert_eq!(parsed.pcm.len(), 1024);
    }

    #[test]
    fn reject_truncated_frame() {
        assert!(parse_audio_frame(&[]).is_err());
        assert!(parse_audio_frame(&[b'A', b'U', b'D', b'0']).is_err());
        assert!(parse_audio_frame(&vec![0u8; 15]).is_err());

        // Header claims 1024 bytes PCM, but body only has 16 bytes
        let mut body = build_valid_packet(1024);
        body.truncate(16);
        assert!(parse_audio_frame(&body).is_err());

        // Body has 16 + 500 bytes instead of 16 + 1024
        let mut body = build_valid_packet(1024);
        body.truncate(16 + 500);
        assert!(parse_audio_frame(&body).is_err());
    }

    #[test]
    fn reject_invalid_tag() {
        let mut body = build_valid_packet(1024);
        body[0..4].copy_from_slice(b"BAD0");
        assert!(parse_audio_frame(&body).is_err());
    }

    #[test]
    fn reject_invalid_sample_rate() {
        let mut body = build_valid_packet(1024);
        body[4..8].copy_from_slice(&44100u32.to_le_bytes());
        assert!(parse_audio_frame(&body).is_err());
    }

    #[test]
    fn reject_invalid_channels() {
        let mut body = build_valid_packet(1024);
        body[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_audio_frame(&body).is_err());
    }

    #[test]
    fn reject_invalid_bits() {
        let mut body = build_valid_packet(1024);
        body[10..12].copy_from_slice(&32u16.to_le_bytes());
        assert!(parse_audio_frame(&body).is_err());
    }

    #[test]
    fn reject_invalid_pcm_lengths() {
        // Zero PCM length
        let mut body = build_valid_packet(0);
        body[12..16].copy_from_slice(&0u32.to_le_bytes());
        body.truncate(16);
        assert!(parse_audio_frame(&body).is_err());

        // Odd PCM length (not divisible by 2 for 16-bit samples)
        let mut body = build_valid_packet(1024);
        body[12..16].copy_from_slice(&513u32.to_le_bytes());
        body.truncate(16 + 513);
        assert!(parse_audio_frame(&body).is_err());

        // Exceeds 2048 bytes limit
        let mut body = build_valid_packet(2048);
        body[12..16].copy_from_slice(&2050u32.to_le_bytes());
        body.resize(16 + 2050, 0);
        assert!(parse_audio_frame(&body).is_err());

        // Extra trailing garbage (body longer than 16 + pcm_len)
        let mut body = build_valid_packet(1024);
        body.push(0xFF);
        assert!(parse_audio_frame(&body).is_err());
    }
}
