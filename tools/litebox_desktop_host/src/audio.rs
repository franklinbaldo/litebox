//! Windows Multimedia (WinMM) waveOut audio module for LiteBox.
//!
//! Provides a safe Rust wrapper around Windows `waveOut*` APIs for PCM audio playback.

use std::cell::UnsafeCell;
use std::time::{Duration, Instant};

use windows_sys::Win32::Media::Audio::{
    waveOutClose, waveOutOpen, waveOutPrepareHeader, waveOutReset, waveOutUnprepareHeader,
    waveOutWrite, HWAVEOUT, WAVEFORMATEX, WAVEHDR, WAVE_FORMAT_PCM, WAVE_MAPPER, WHDR_DONE,
};

pub const DEFAULT_SAMPLE_RATE: u32 = 22050;

#[derive(Clone, Debug, Default)]
pub struct AudioMetrics {
    pub submitted: usize,
    pub completed: usize,
    pub canceled: usize,
    pub non_silent: usize,
    pub errors: Vec<String>,
}

/// A single pending waveOut buffer. The WAVEHDR pointer and data Vec must outlive
/// the waveOutWrite call. Both are kept alive inside this struct until confirmed done.
/// Safety: HWAVEOUT, *mut u8 inside WAVEHDR are Windows handles valid for the thread
/// that opened the device; we wrap in Mutex or ensure single-threaded ownership.
pub struct WaveBuffer {
    pub hdr: Box<UnsafeCell<WAVEHDR>>,
    /// Keeps the data allocation alive until the driver marks WHDR_DONE.
    pub _data: Vec<u8>,
}

pub struct WinMMAudio {
    pub hwave: HWAVEOUT,
    pub pending: Vec<WaveBuffer>,
    pub metrics: AudioMetrics,
}

// SAFETY: HWAVEOUT is a kernel handle. We never share it across threads without
// Mutex protection. All waveOut* calls happen under the Mutex lock or thread ownership.
unsafe impl Send for WinMMAudio {}

impl WinMMAudio {
    pub fn open() -> Option<(Self, bool)> {
        Self::open_with_format(DEFAULT_SAMPLE_RATE, 1, 16)
    }

    pub fn open_with_format(
        sample_rate: u32,
        channels: u16,
        bits_per_sample: u16,
    ) -> Option<(Self, bool)> {
        let mut hwave: HWAVEOUT = std::ptr::null_mut();
        let block_align = channels * (bits_per_sample / 8);
        let avg_bytes_per_sec = sample_rate * u32::from(block_align);
        let wfx = WAVEFORMATEX {
            wFormatTag: WAVE_FORMAT_PCM as u16,
            nChannels: channels,
            nSamplesPerSec: sample_rate,
            nAvgBytesPerSec: avg_bytes_per_sec,
            nBlockAlign: block_align,
            wBitsPerSample: bits_per_sample,
            cbSize: 0,
        };
        let res = unsafe { waveOutOpen(&mut hwave, WAVE_MAPPER, &wfx, 0, 0, 0) };
        if res != 0 {
            eprintln!("[audio] waveOutOpen failed MMRESULT={res}");
            return None;
        }
        Some((
            WinMMAudio {
                hwave,
                pending: Vec::new(),
                metrics: AudioMetrics::default(),
            },
            true,
        ))
    }

    pub fn empty(errors: Vec<String>) -> Self {
        WinMMAudio {
            hwave: std::ptr::null_mut(),
            pending: Vec::new(),
            metrics: AudioMetrics {
                submitted: 0,
                completed: 0,
                canceled: 0,
                non_silent: 0,
                errors,
            },
        }
    }

    pub fn is_open(&self) -> bool {
        !self.hwave.is_null()
    }

    /// Sweep buffers the driver has marked done.
    pub fn reap_done(&mut self) {
        let mut i = 0;
        while i < self.pending.len() {
            // The driver updates this field asynchronously; never create a Rust
            // shared reference to the header while it is owned by WinMM.
            let flags =
                unsafe { std::ptr::addr_of!((*self.pending[i].hdr.get()).dwFlags).read_volatile() };
            if (flags & WHDR_DONE) != 0 {
                let buf = self.pending.swap_remove(i);
                let r =
                    unsafe { waveOutUnprepareHeader(self.hwave, buf.hdr.get(), size_of_wavehdr()) };
                if r != 0 {
                    self.metrics
                        .errors
                        .push(format!("waveOutUnprepareHeader MMRESULT={r}"));
                    // Do not free a buffer that the OS may still own.
                    std::mem::forget(buf);
                }
                self.metrics.completed += 1;
            } else {
                i += 1;
            }
        }
    }

    pub fn play(&mut self, pcm: &[u8]) -> bool {
        if self.hwave.is_null() || pcm.is_empty() {
            return false;
        }
        // unsigned_abs avoids overflow for i16::MIN (-32768)
        let non_silent = pcm
            .chunks_exact(2)
            .any(|c| i16::from_le_bytes([c[0], c[1]]).unsigned_abs() > 100);
        if non_silent {
            self.metrics.non_silent += 1;
        }

        self.reap_done();
        if self.pending.len() >= 4 {
            self.metrics.canceled += 1;
            return false;
        }

        let mut data = pcm.to_vec();
        let hdr = Box::new(UnsafeCell::new(WAVEHDR {
            lpData: data.as_mut_ptr(),
            dwBufferLength: data.len() as u32,
            dwBytesRecorded: 0,
            dwUser: 0,
            dwFlags: 0,
            dwLoops: 0,
            lpNext: std::ptr::null_mut(),
            reserved: 0,
        }));

        let r = unsafe { waveOutPrepareHeader(self.hwave, hdr.get(), size_of_wavehdr()) };
        if r != 0 {
            self.metrics
                .errors
                .push(format!("waveOutPrepareHeader MMRESULT={r}"));
            return false;
        }

        let r = unsafe { waveOutWrite(self.hwave, hdr.get(), size_of_wavehdr()) };
        if r != 0 {
            self.metrics
                .errors
                .push(format!("waveOutWrite MMRESULT={r}"));
            // Safely unprepare without freeing: the driver never touched this one.
            let ru = unsafe { waveOutUnprepareHeader(self.hwave, hdr.get(), size_of_wavehdr()) };
            if ru != 0 {
                self.metrics
                    .errors
                    .push(format!("waveOutUnprepareHeader rollback MMRESULT={ru}"));
                std::mem::forget(WaveBuffer { hdr, _data: data });
            }
            return false;
        }

        self.metrics.submitted += 1;
        // Keep data alive inside pending; drop only after WHDR_DONE.
        self.pending.push(WaveBuffer { hdr, _data: data });
        true
    }

    /// Submit PCM buffer and wait synchronously until the driver marks WHDR_DONE.
    /// Returns Ok(()) once WHDR_DONE is reached and header unprepare succeeded.
    pub fn play_and_wait(&mut self, pcm: &[u8], timeout: Duration) -> Result<(), String> {
        if !self.pending.is_empty() || !self.metrics.errors.is_empty() {
            return Err("synchronous playback requires an idle, healthy device".into());
        }
        let prev_completed = self.metrics.completed;
        if !self.play(pcm) {
            return Err(self
                .metrics
                .errors
                .last()
                .cloned()
                .unwrap_or_else(|| "play failed or buffer dropped".into()));
        }
        let start = Instant::now();
        while self.metrics.completed == prev_completed {
            self.reap_done();
            if let Some(error) = self.metrics.errors.last() {
                return Err(error.clone());
            }
            if self.metrics.completed > prev_completed {
                break;
            }
            if !self.metrics.errors.is_empty() && self.pending.is_empty() {
                return Err(self
                    .metrics
                    .errors
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "audio error during playback".into()));
            }
            if start.elapsed() > timeout {
                return Err("audio playback timeout waiting for WHDR_DONE".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    /// Graceful close: drain naturally-done buffers, reset (cancels in-flight),
    /// then unprepare remaining. Checks every return code.
    pub fn close(&mut self) {
        if self.hwave.is_null() {
            return;
        }
        self.reap_done();
        let r = unsafe { waveOutReset(self.hwave) };
        if r != 0 {
            self.metrics
                .errors
                .push(format!("waveOutReset MMRESULT={r}"));
            for buffer in self.pending.drain(..) {
                std::mem::forget(buffer);
            }
            // Keep the failed device alive until process exit rather than free
            // memory which a malfunctioning driver might continue to reference.
            self.hwave = std::ptr::null_mut();
            return;
        }
        // After Reset, remaining buffers are marked WHDR_DONE by driver.
        for buf in self.pending.drain(..) {
            let r = unsafe { waveOutUnprepareHeader(self.hwave, buf.hdr.get(), size_of_wavehdr()) };
            if r != 0 {
                self.metrics
                    .errors
                    .push(format!("waveOutUnprepareHeader cleanup MMRESULT={r}"));
                std::mem::forget(buf);
            }
            self.metrics.canceled += 1;
        }
        let r = unsafe { waveOutClose(self.hwave) };
        if r != 0 {
            self.metrics
                .errors
                .push(format!("waveOutClose MMRESULT={r}"));
        }
        self.hwave = std::ptr::null_mut();
    }
}

impl Drop for WinMMAudio {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn size_of_wavehdr() -> u32 {
    std::mem::size_of::<WAVEHDR>() as u32
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waveout_open_close() {
        if let Some((mut audio, ok)) = WinMMAudio::open() {
            assert!(ok);
            assert!(audio.is_open());
            audio.close();
        } else {
            eprintln!("WinMM audio device not available");
        }
    }
}
