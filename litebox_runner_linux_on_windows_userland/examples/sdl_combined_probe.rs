#![cfg(windows)]
use litebox_desktop_host::WinMMAudio;
pub const EXPECTED_RATE: u32 = 22050;
pub const EXPECTED_CHANNELS: u16 = 1;
pub const EXPECTED_BITS: u16 = 16;
pub const MAX_PCM_BYTES: usize = 2048;
pub const WIDTH: usize = 160;
pub const HEIGHT: usize = 120;
pub const PIXELS: usize = WIDTH * HEIGHT * 3;
#[cfg(windows)]
use litebox_platform_windows_userland::{WindowsUserland, run_thread};
use litebox_shim_linux::host_pipe::{HostReader, HostWriter};
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, GetDC, ReleaseDC, SRCCOPY, StretchDIBits,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
    PostQuitMessage, RegisterClassW, SW_SHOW, ShowWindow, WM_CLOSE, WM_DESTROY, WM_QUIT, WNDCLASSW,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

const AUD0_MAGIC: [u8; 4] = *b"AUD0";
const ACK0_PAYLOAD: [u8; 4] = *b"ACK0";

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

fn parse_frame(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(body.len() == 8 + PIXELS, "invalid frame length");
    anyhow::ensure!(&body[..4] == b"FRAM", "invalid frame tag");
    anyhow::ensure!(
        u16::from_le_bytes([body[4], body[5]]) == 160
            && u16::from_le_bytes([body[6], body[7]]) == 120,
        "unsupported dimensions"
    );
    Ok(body[8..].to_vec())
}

#[allow(dead_code)]
struct AudioPacket {
    rate: u32,
    channels: u16,
    bits: u16,
    pcm: Vec<u8>,
}

fn parse_audio_frame(body: &[u8]) -> anyhow::Result<AudioPacket> {
    anyhow::ensure!(body.len() >= 16, "frame too short: {} bytes", body.len());
    let magic = &body[0..4];
    anyhow::ensure!(magic == AUD0_MAGIC, "invalid magic: {magic:?}");
    let rate = u32::from_le_bytes(body[4..8].try_into().unwrap());
    anyhow::ensure!(rate == EXPECTED_RATE, "unsupported rate: {rate}");
    let channels = u16::from_le_bytes(body[8..10].try_into().unwrap());
    anyhow::ensure!(
        channels == EXPECTED_CHANNELS,
        "unsupported channels: {channels}"
    );
    let bits = u16::from_le_bytes(body[10..12].try_into().unwrap());
    anyhow::ensure!(bits == EXPECTED_BITS, "unsupported bits: {bits}");
    let pcm_len = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
    anyhow::ensure!(pcm_len > 0, "pcm length cannot be zero");
    anyhow::ensure!(
        pcm_len.is_multiple_of(2),
        "pcm length must be even: {pcm_len}"
    );
    anyhow::ensure!(
        pcm_len <= MAX_PCM_BYTES,
        "pcm length {pcm_len} exceeds limit {MAX_PCM_BYTES}"
    );
    anyhow::ensure!(body.len() == 16 + pcm_len, "exact length mismatch");
    Ok(AudioPacket {
        rate,
        channels,
        bits,
        pcm: body[16..].to_vec(),
    })
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn show_frames(rx: mpsc::Receiver<Vec<u8>>, output: std::path::PathBuf) -> Result<usize, String> {
    unsafe {
        let class_name = wide("LiteBoxSdlProbe");
        let title = wide("SDL2 Linux on LiteBox - combined probe");
        let instance = GetModuleHandleW(std::ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            ..std::mem::zeroed()
        };
        if RegisterClassW(&raw const wc) == 0 {
            return Err("RegisterClassW failed".into());
        }
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            100,
            100,
            500,
            410,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return Err("CreateWindowExW failed".into());
        }
        ShowWindow(hwnd, SW_SHOW);
        let hold = std::env::var("LITEBOX_VIDEO_HOLD_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2)
            .clamp(2, 30);
        let started = Instant::now();
        let mut count = 0;
        let mut last = Vec::new();
        let mut ended = None;
        let mut failure = None;
        loop {
            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT {
                    return Err("window closed before completion".into());
                }
                DispatchMessageW(&raw const msg);
            }
            match rx.try_recv() {
                Ok(rgb) => {
                    let expected = [[255, 0, 0], [0, 255, 0], [0, 0, 255]];
                    if count < 3 {
                        if rgb[..3] != expected[count] {
                            failure = Some(format!(
                                "SDL background pixel differs: expected {:?}, got {:?}",
                                expected[count],
                                &rgb[..3]
                            ));
                            break;
                        }
                        // Validate the moving rectangle
                        let rect_x = 60 + count * 10;
                        let center_pixel_offset = (45 * WIDTH + rect_x + 20) * 3;
                        if rgb[center_pixel_offset..center_pixel_offset + 3] != [255, 255, 255] {
                            failure = Some(
                                "SDL white center rectangle not found at expected position"
                                    .to_string(),
                            );
                            break;
                        }
                    }
                    count += 1;
                    last = rgb;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    ended.get_or_insert_with(Instant::now);
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if !last.is_empty() {
                let mut bgra = Vec::with_capacity(WIDTH * HEIGHT * 4);
                for rgb in last.as_chunks::<3>().0 {
                    bgra.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
                }
                let mut info: BITMAPINFO = std::mem::zeroed();
                info.bmiHeader = BITMAPINFOHEADER {
                    biSize: u32::try_from(std::mem::size_of::<BITMAPINFOHEADER>()).unwrap(),
                    biWidth: 160,
                    biHeight: -120,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    ..std::mem::zeroed()
                };
                let dc = GetDC(hwnd);
                if dc.is_null() {
                    failure = Some("GetDC failed".into());
                    break;
                }
                let rows = StretchDIBits(
                    dc,
                    0,
                    0,
                    480,
                    360,
                    0,
                    0,
                    160,
                    120,
                    bgra.as_ptr().cast(),
                    &raw const info,
                    DIB_RGB_COLORS,
                    SRCCOPY,
                );
                ReleaseDC(hwnd, dc);
                if rows <= 0 {
                    failure = Some("StretchDIBits failed".into());
                    break;
                }
            }
            if ended.is_some_and(|t| t.elapsed() >= Duration::from_secs(hold)) {
                break;
            }
            if started.elapsed() > Duration::from_secs(hold + 12) {
                failure = Some("video timeout".into());
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        DestroyWindow(hwnd);
        if let Some(err) = failure {
            return Err(err);
        }
        if count != 3 {
            return Err(format!("expected 3 frames, got {count}"));
        }
        let mut ppm = b"P6\n160 120\n255\n".to_vec();
        ppm.extend_from_slice(&last);
        std::fs::write(output, ppm).map_err(|e| e.to_string())?;
        Ok(count)
    }
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
    let tar_path = std::env::args_os().nth(1).expect("combined probe TAR path");
    let output = std::env::args_os().nth(2).expect("received frame PPM path");
    let platform = WindowsUserland::new();
    let builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let fs = builder.default_fs(
        litebox::fs::in_mem::InMem::new_initialized::<&str>([]),
        std::fs::read(tar_path)?.into(),
    );
    let shim = builder.build();
    let mut program = shim.load_program(
        std::sync::Arc::new(fs),
        platform.init_task(),
        "/bin/probe",
        vec![std::ffi::CString::new("probe")?],
        vec![
            std::ffi::CString::new("SDL_VIDEODRIVER=litebox")?,
            std::ffi::CString::new("SDL_AUDIODRIVER=litebox")?,
        ],
    )?;

    // Video FDs: 3/4
    let (v_in, v_writer) = program.attach_host_input()?;
    let (v_out, v_reader) = program.attach_host_output()?;

    // Audio FDs: 5/6
    let (a_in, a_writer) = program.attach_host_input()?;
    let (a_out, a_reader) = program.attach_host_output()?;

    anyhow::ensure!(
        (v_in, v_out, a_in, a_out) == (3, 4, 5, 6),
        "unexpected fixture descriptors"
    );

    let (tx, rx) = mpsc::sync_channel(1);

    let video_thread = std::thread::spawn(move || -> Result<(), String> {
        let mut wire =
            litebox_desktop_transport::Framed::new(Reader(v_reader), Writer(v_writer), 1_048_576)
                .map_err(|e| e.to_string())?;
        eprintln!("host: video handshake waiting");
        wire.handshake(0).map_err(|e| e.to_string())?;
        eprintln!("host: video handshake complete");

        let mut received = 0;
        while let Some(body) = wire.recv().map_err(|e| e.to_string())? {
            eprintln!("host: received video {} bytes", body.len());
            tx.send(parse_frame(&body).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            received += 1;
            // Synthetic input logic: moving rectangle
            if received == 1 {
                wire.send(b"KEY0\x4f\x00\x01\x00")
                    .map_err(|e| e.to_string())?;
            } else if received == 2 {
                wire.send(b"KEY0\x4f\x00\x00\x00")
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    });

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

            for chunk in packet.pcm.as_chunks::<2>().0 {
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

            audio_device
                .play_and_wait(&packet.pcm, Duration::from_secs(2))
                .map_err(|e| {
                    anyhow::anyhow!("WinMM playback error on buffer {received_count}: {e}")
                })?;

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

    let gui = std::thread::spawn(move || show_frames(rx, output.into()));

    unsafe {
        #[cfg(windows)]
        run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    eprintln!("guest: run_thread returned");
    let exit = program.process.wait();
    eprintln!("guest: exit {exit}");

    video_thread
        .join()
        .expect("video receiver panicked")
        .map_err(anyhow::Error::msg)?;
    let frames = gui
        .join()
        .expect("GUI panicked")
        .map_err(anyhow::Error::msg)?;
    let stats = audio_thread.join().expect("audio thread panicked")?;

    anyhow::ensure!(exit == 0, "guest exited with non-zero code {exit}");

    // Video verification
    println!("SDL_VIDEO_OK: {frames} verified frames presented with GDI; guest exit 0");

    // Audio verification
    anyhow::ensure!(
        stats.completed >= 8,
        "fewer than 8 buffers completed: {}",
        stats.completed
    );
    anyhow::ensure!(stats.errors == 0, "audio errors occurred: {}", stats.errors);
    anyhow::ensure!(
        stats.received == stats.submitted && stats.submitted == stats.completed,
        "audio buffer counts differ"
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
    println!(
        "SDL_COMBINED_OK: Video, input, and audio streams completed concurrently with clean shutdown."
    );

    Ok(())
}

#[cfg(not(windows))]
fn main() {}
