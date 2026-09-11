//! LiteBox Native Desktop Host (Rust/Win32)
//!
//! Windows-native replacement for host.py. Launches the LiteBox runner with a guest ELF TAR
//! via stdin/stdout binary protocol (FRAM/SND0/TICK/KEYP/KEYR), renders frames via GDI DIB,
//! plays audio via WinMM waveOut.
//!
//! No Python runtime required. No hardcoded user paths.

use litebox_desktop_host::audio::WinMMAudio;
use litebox_desktop_host::protocol;

use std::env;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
    SetStretchBltMode, StretchBlt, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, COLORONCOLOR,
    DIB_RGB_COLORS, RGBQUAD, SRCCOPY,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRect, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetWindowLongPtrW, PeekMessageW, PostQuitMessage, RegisterClassW, SetWindowLongPtrW,
    ShowWindow, GWLP_USERDATA, MSG, PM_REMOVE, SW_SHOW, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND,
    WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WNDCLASSW, WS_CAPTION, WS_MINIMIZEBOX, WS_OVERLAPPED,
    WS_SYSMENU, WS_VISIBLE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, LoadCursorW, LoadIconW, LoadImageW, IDC_ARROW, IDI_APPLICATION, IMAGE_ICON,
    LR_LOADFROMFILE,
};

/// CREATE_NO_WINDOW flag: hides the child process console window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const GUEST_WIDTH: u32 = 160;
const GUEST_HEIGHT: u32 = 120;
const SCALE: u32 = 3;
const DISPLAY_WIDTH: u32 = GUEST_WIDTH * SCALE;
const DISPLAY_HEIGHT: u32 = GUEST_HEIGHT * SCALE;
const FRAME_INTERVAL: Duration = Duration::from_micros(33_333);

// Key codes in the guest protocol
const KEY_LEFT: u8 = 1;
const KEY_RIGHT: u8 = 2;
const KEY_SPACE: u8 = 3;

// --- Atomic key state (shared between WndProc and input writer thread) -----
/// Bitmask: bit 0=left, bit 1=right, bit 2=space
static DESIRED_KEYS: AtomicU8 = AtomicU8::new(0);

// --- Shared state accessed from multiple threads ----------------------------
struct FrameBuffer {
    rgb: Vec<u8>,
    new_frame: bool,
}

// --- Shared app state passed via Arc ----------------------------------------
struct AppState {
    frame: Mutex<FrameBuffer>,
    audio: Mutex<WinMMAudio>,
    audio_opened: bool,
    running: AtomicBool,
    rendered_frames: Mutex<usize>,
    errors: Mutex<Vec<String>>,
    /// Guest exited unexpectedly (before smoke timeout).
    guest_exit_unexpected: AtomicBool,
    /// Guest exit code if set.
    guest_exit_code: Mutex<Option<i32>>,
    /// stdin write queue: sequences of bytes to send
    stdin_queue: Mutex<Vec<Vec<u8>>>,
}

fn queue_key(state: &AppState, packet: Vec<u8>) {
    let mut queue = state.stdin_queue.lock().unwrap();
    if queue.len() >= 64 {
        state
            .errors
            .lock()
            .unwrap()
            .push("Input queue overflow".into());
        state.running.store(false, Ordering::Relaxed);
    } else {
        queue.push(packet);
    }
}

// --- Win32 window procedure --------------------------------------------------
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Retrieve AppState from GWLP_USERDATA if set
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const AppState;

    match msg {
        WM_ERASEBKGND => 1, // Prevent background flicker
        WM_KILLFOCUS => {
            // Clear all desired keys on focus loss (handled in WndProc, not just PeekMessage)
            DESIRED_KEYS.store(0, Ordering::Relaxed);
            // Queue KEYR for any pressed keys
            if !state_ptr.is_null() {
                let state = &*state_ptr;
                for key in [KEY_LEFT, KEY_RIGHT, KEY_SPACE] {
                    queue_key(state, vec![b'K', b'E', b'Y', b'R', key]);
                }
            }
            0
        }
        WM_KEYDOWN => {
            let vk = wparam as u32;
            let bit = match vk {
                0x25 | 0x41 => Some((1u8, KEY_LEFT)),  // Left / A
                0x27 | 0x44 => Some((2u8, KEY_RIGHT)), // Right / D
                0x20 => Some((4u8, KEY_SPACE)),        // Space
                0x1B => {
                    // ESC: signal shutdown
                    if !state_ptr.is_null() {
                        (*state_ptr).running.store(false, Ordering::Relaxed);
                    }
                    return 0;
                }
                _ => None,
            };
            if let Some((mask, code)) = bit {
                let old = DESIRED_KEYS.fetch_or(mask, Ordering::Relaxed);
                if old & mask == 0 {
                    // Rising edge: enqueue KEYP
                    if !state_ptr.is_null() {
                        let state = &*state_ptr;
                        queue_key(state, vec![b'K', b'E', b'Y', b'P', code]);
                    }
                }
            }
            0
        }
        WM_KEYUP => {
            let vk = wparam as u32;
            let bit = match vk {
                0x25 | 0x41 => Some((1u8, KEY_LEFT)),
                0x27 | 0x44 => Some((2u8, KEY_RIGHT)),
                0x20 => Some((4u8, KEY_SPACE)),
                _ => None,
            };
            if let Some((mask, code)) = bit {
                let old = DESIRED_KEYS.fetch_and(!mask, Ordering::Relaxed);
                if old & mask != 0 {
                    // Falling edge: enqueue KEYR
                    if !state_ptr.is_null() {
                        let state = &*state_ptr;
                        queue_key(state, vec![b'K', b'E', b'Y', b'R', code]);
                    }
                }
            }
            0
        }
        WM_CLOSE => {
            if !state_ptr.is_null() {
                (*state_ptr).running.store(false, Ordering::Relaxed);
            }
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

// --- Main --------------------------------------------------------------------
fn main() {
    let args: Vec<String> = env::args().collect();

    let mut runner_path: Option<String> = None;
    let mut tar_path: Option<String> = None;
    let mut smoke_seconds: Option<f64> = None;
    let mut app_id = String::from("LiteBox.Game.Breakout");
    let mut icon_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--app-id" if i + 1 < args.len() => {
                app_id = args[i + 1].clone();
                i += 2;
            }
            "--icon" if i + 1 < args.len() => {
                icon_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--runner" if i + 1 < args.len() => {
                runner_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--tar" if i + 1 < args.len() => {
                tar_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--smoke-seconds" if i + 1 < args.len() => {
                smoke_seconds = match args[i + 1].parse::<f64>() {
                    Ok(value) if value.is_finite() && value > 0.0 => Some(value),
                    _ => {
                        eprintln!("Invalid --smoke-seconds");
                        std::process::exit(2);
                    }
                };
                i += 2;
            }
            _ => {
                eprintln!("Unknown or incomplete argument: {}", args[i]);
                std::process::exit(2);
            }
        }
    }

    let runner_path = match runner_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --runner <path-to-runner-exe> is required");
            std::process::exit(1);
        }
    };
    let tar_path = match tar_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --tar <path-to-game.tar> is required");
            std::process::exit(1);
        }
    };

    if !std::path::Path::new(&runner_path).exists() {
        eprintln!("Error: runner not found: {}", runner_path);
        std::process::exit(1);
    }
    if !std::path::Path::new(&tar_path).exists() {
        eprintln!("Error: TAR not found: {}", tar_path);
        std::process::exit(1);
    }

    if app_id.is_empty() || app_id.len() > 128 || app_id.contains([' ', '\0']) {
        eprintln!("Invalid --app-id");
        std::process::exit(2);
    }
    if unsafe { SetCurrentProcessExplicitAppUserModelID(to_wide(&app_id).as_ptr()) } < 0 {
        eprintln!("Failed to set application identity");
        std::process::exit(1);
    }
    let icon = if let Some(path) = &icon_path {
        unsafe {
            LoadImageW(
                std::ptr::null_mut(),
                to_wide(path).as_ptr(),
                IMAGE_ICON,
                32,
                32,
                LR_LOADFROMFILE,
            )
        }
    } else {
        unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) }
    };
    if icon.is_null() {
        eprintln!("Failed to load application icon");
        std::process::exit(1);
    }

    // Open audio device (optional: host works without it)
    let (audio_device, audio_opened) = match WinMMAudio::open() {
        Some((a, ok)) => (a, ok),
        None => (
            WinMMAudio::empty(vec!["Audio device unavailable".into()]),
            false,
        ),
    };

    let state = Arc::new(AppState {
        frame: Mutex::new(FrameBuffer {
            rgb: vec![0u8; (GUEST_WIDTH * GUEST_HEIGHT * 3) as usize],
            new_frame: false,
        }),
        audio: Mutex::new(audio_device),
        audio_opened,
        running: AtomicBool::new(true),
        rendered_frames: Mutex::new(0),
        errors: Mutex::new(Vec::new()),
        guest_exit_unexpected: AtomicBool::new(false),
        guest_exit_code: Mutex::new(None),
        stdin_queue: Mutex::new(Vec::new()),
    });

    // Spawn runner with CREATE_NO_WINDOW to suppress its console
    let child_result = Command::new(&runner_path)
        .arg("--initial-files")
        .arg(&tar_path)
        .arg("/bin/breakout")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();

    let mut child = match child_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: failed to spawn runner: {}", e);
            std::process::exit(1);
        }
    };

    let stdin_pipe = child.stdin.take().expect("stdin");
    let mut stdout_pipe = child.stdout.take().expect("stdout");
    let mut stderr_pipe = child.stderr.take().expect("stderr");

    // --- Thread: stdin writer (non-blocking from UI thread) -----------------
    // Consumes from stdin_queue; also sends TICK when running.
    // This thread owns the stdin handle so UI thread never blocks on write.
    let state_writer = Arc::clone(&state);
    let writer_handle = {
        let mut stdin_wr = stdin_pipe;
        thread::spawn(move || {
            let mut next_tick = Instant::now();
            while state_writer.running.load(Ordering::Relaxed) {
                // Drain input queue first
                let packets: Vec<Vec<u8>> = {
                    let mut q = state_writer.stdin_queue.lock().unwrap();
                    std::mem::take(&mut *q)
                };
                for pkt in &packets {
                    if stdin_wr.write_all(pkt).is_err() {
                        state_writer.running.store(false, Ordering::Relaxed);
                        return;
                    }
                }
                if !packets.is_empty() {
                    let _ = stdin_wr.flush();
                }

                // Send TICK at 30 fps
                let now = Instant::now();
                if now >= next_tick {
                    if stdin_wr.write_all(b"TICK").is_err() || stdin_wr.flush().is_err() {
                        state_writer.running.store(false, Ordering::Relaxed);
                        return;
                    }
                    next_tick += FRAME_INTERVAL;
                    if next_tick < now {
                        next_tick = now + FRAME_INTERVAL;
                    }
                }

                // Sleep briefly (< 1ms busy waste but stays responsive)
                thread::sleep(Duration::from_millis(1));
            }
        })
    };

    // --- Thread: stdout reader (FRAM/SND0) ----------------------------------
    let state_reader = Arc::clone(&state);
    let reader_handle = thread::spawn(move || {
        let mut frame = [0; protocol::WIDTH * protocol::HEIGHT * 3];
        let mut pcm = [0; protocol::SAMPLES * 2];
        loop {
            match protocol::read_packet(&mut stdout_pipe, &mut frame, &mut pcm) {
                Ok(Some(protocol::Packet::Frame)) => {
                    let mut fb = state_reader.frame.lock().unwrap();
                    fb.rgb.copy_from_slice(&frame);
                    fb.new_frame = true;
                }
                Ok(Some(protocol::Packet::Audio)) => {
                    state_reader.audio.lock().unwrap().play(&pcm);
                }
                Ok(None) => {
                    if state_reader.running.load(Ordering::Relaxed) {
                        state_reader
                            .errors
                            .lock()
                            .unwrap()
                            .push("Unexpected guest output EOF".into());
                        state_reader.running.store(false, Ordering::Relaxed);
                    }
                    break;
                }
                Err(error) => {
                    state_reader
                        .errors
                        .lock()
                        .unwrap()
                        .push(format!("Protocol: {error}"));
                    state_reader.running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    // --- Thread: stderr drainer (capture for error logging) -----------------
    let stderr_handle = thread::spawn(move || {
        let mut retained = Vec::new();
        let mut bytes = [0; 1024];
        loop {
            match stderr_pipe.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    retained.extend_from_slice(&bytes[..count]);
                    if retained.len() > 4096 {
                        retained.drain(..retained.len() - 4096);
                    }
                }
            }
        }
        retained
    });

    // --- Create Win32 window -------------------------------------------------
    let h_instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let class_name = to_wide("LiteBoxNativeHostClass");
    let title = to_wide("Breakout - LiteBox Native");

    let wndclass = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(window_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: h_instance,
        hIcon: icon,
        hCursor: unsafe { LoadCursorW(std::ptr::null_mut(), IDC_ARROW) },
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    unsafe { RegisterClassW(&wndclass) };

    let mut rect = RECT {
        left: 0,
        top: 0,
        right: DISPLAY_WIDTH as i32,
        bottom: DISPLAY_HEIGHT as i32,
    };
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
    unsafe { AdjustWindowRect(&mut rect, style, 0) };

    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            style,
            100,
            100,
            rect.right - rect.left,
            rect.bottom - rect.top,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            h_instance,
            std::ptr::null(),
        )
    };
    if hwnd.is_null() {
        eprintln!("Error: CreateWindowExW failed");
        state.running.store(false, Ordering::Relaxed);
        // Cleanup happens below
    }

    // Associate AppState pointer with window for WndProc access
    if !hwnd.is_null() {
        let state_raw: *const AppState = Arc::as_ptr(&state);
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_raw as isize) };
        unsafe { ShowWindow(hwnd, SW_SHOW) };
    }

    // --- GDI DIB for 160-120 ? 480-360 rendering ----------------------------
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: GUEST_WIDTH as i32,
            biHeight: -(GUEST_HEIGHT as i32), // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: GUEST_WIDTH * GUEST_HEIGHT * 4,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }; 1],
    };

    let mut dib_pixels: *mut std::ffi::c_void = std::ptr::null_mut();
    let hdc_screen = if hwnd.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { GetDC(hwnd) }
    };
    let hdc_mem = if hdc_screen.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { CreateCompatibleDC(hdc_screen) }
    };
    let hbitmap = if hdc_mem.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe {
            CreateDIBSection(
                hdc_mem,
                &bmi,
                DIB_RGB_COLORS,
                &mut dib_pixels,
                std::ptr::null_mut(),
                0,
            )
        }
    };
    if hwnd.is_null()
        || hdc_screen.is_null()
        || hdc_mem.is_null()
        || hbitmap.is_null()
        || dib_pixels.is_null()
    {
        state
            .errors
            .lock()
            .unwrap()
            .push("Window/GDI allocation failed".into());
        state.running.store(false, Ordering::Relaxed);
    }
    let old_bmp = if !hdc_mem.is_null() && !hbitmap.is_null() {
        unsafe { SelectObject(hdc_mem, hbitmap) }
    } else {
        std::ptr::null_mut()
    };

    let start_time = Instant::now();
    let mut msg: MSG = unsafe { std::mem::zeroed() };

    // --- Main loop -----------------------------------------------------------
    while state.running.load(Ordering::Relaxed) {
        // Process Win32 messages
        while unsafe { PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            if msg.message == windows_sys::Win32::UI::WindowsAndMessaging::WM_QUIT {
                state.running.store(false, Ordering::Relaxed);
                break;
            }
            unsafe { DispatchMessageW(&msg) };
        }

        if !state.running.load(Ordering::Relaxed) {
            break;
        }

        // Render frame if new
        if !dib_pixels.is_null() && !hdc_mem.is_null() {
            let mut fb = state.frame.lock().unwrap();
            if fb.new_frame {
                let src = &fb.rgb;
                let dst = unsafe {
                    std::slice::from_raw_parts_mut(
                        dib_pixels as *mut u8,
                        (GUEST_WIDTH * GUEST_HEIGHT * 4) as usize,
                    )
                };
                // Convert RGB24 ? BGRA32
                for (s, d) in src.chunks_exact(3).zip(dst.chunks_exact_mut(4)) {
                    d[0] = s[2]; // B
                    d[1] = s[1]; // G
                    d[2] = s[0]; // R
                    d[3] = 255;
                }
                fb.new_frame = false;
                drop(fb);

                if !hwnd.is_null() {
                    let hdc = unsafe { GetDC(hwnd) };
                    if !hdc.is_null() {
                        unsafe {
                            SetStretchBltMode(hdc, COLORONCOLOR);
                            StretchBlt(
                                hdc,
                                0,
                                0,
                                DISPLAY_WIDTH as i32,
                                DISPLAY_HEIGHT as i32,
                                hdc_mem,
                                0,
                                0,
                                GUEST_WIDTH as i32,
                                GUEST_HEIGHT as i32,
                                SRCCOPY,
                            );
                            ReleaseDC(hwnd, hdc);
                        }
                    }
                }
                *state.rendered_frames.lock().unwrap() += 1;
            }
        }

        // Check if child exited
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(-1);
                *state.guest_exit_code.lock().unwrap() = Some(code);
                if code != 0 {
                    state.guest_exit_unexpected.store(true, Ordering::Relaxed);
                    state
                        .errors
                        .lock()
                        .unwrap()
                        .push(format!("Guest exited with non-zero code {}", code));
                }
                state.running.store(false, Ordering::Relaxed);
                break;
            }
            Ok(None) => {}
            Err(e) => {
                state
                    .errors
                    .lock()
                    .unwrap()
                    .push(format!("try_wait error: {}", e));
                state.running.store(false, Ordering::Relaxed);
                break;
            }
        }

        // Smoke timeout
        if let Some(secs) = smoke_seconds {
            if start_time.elapsed().as_secs_f64() >= secs {
                break;
            }
        }

        thread::sleep(Duration::from_millis(2));
    }

    state.running.store(false, Ordering::Relaxed);

    // --- GDI cleanup ---------------------------------------------------------
    if !hdc_mem.is_null() && !old_bmp.is_null() {
        unsafe { SelectObject(hdc_mem, old_bmp) };
    }
    if !hbitmap.is_null() {
        unsafe { DeleteObject(hbitmap) };
    }
    if !hdc_mem.is_null() {
        unsafe { DeleteDC(hdc_mem) };
    }
    if !hdc_screen.is_null() {
        unsafe { ReleaseDC(hwnd, hdc_screen) };
    }
    if !hwnd.is_null() {
        unsafe { DestroyWindow(hwnd) };
    }
    if icon_path.is_some() {
        unsafe {
            DestroyIcon(icon);
        }
    }

    // --- Graceful child shutdown ----------------------------------------------
    // Close stdin to signal EOF to guest; wait up to 2 seconds, then kill.
    // We cannot drop stdin here because the writer thread owns it.
    // Signal writer thread to stop (already done via running=false), wait for it.
    // Do not join a potentially blocked writer before the process grace timeout.
    // On timeout, terminating our child closes its read end and releases the writer.
    let exit_code = {
        let grace = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    *state.guest_exit_code.lock().unwrap() = status.code();
                    break status.code();
                }
                Ok(None) if grace.elapsed() < Duration::from_secs(2) => {
                    thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    state
                        .errors
                        .lock()
                        .unwrap()
                        .push("Guest required forced termination".into());
                    eprintln!("[host] Grace timeout; killing guest process");
                    let _ = child.kill();
                    let s = child.wait().ok();
                    break s.and_then(|s| s.code());
                }
            }
        }
    };

    if writer_handle.join().is_err() {
        state
            .errors
            .lock()
            .unwrap()
            .push("Writer thread panicked".into());
    }
    if reader_handle.join().is_err() {
        state
            .errors
            .lock()
            .unwrap()
            .push("Reader thread panicked".into());
    }
    match stderr_handle.join() {
        Ok(bytes) if !bytes.is_empty() => {
            eprintln!("[guest stderr] {}", String::from_utf8_lossy(&bytes))
        }
        Err(_) => state
            .errors
            .lock()
            .unwrap()
            .push("Stderr reader panicked".into()),
        _ => {}
    }
    if exit_code != Some(0) {
        state
            .errors
            .lock()
            .unwrap()
            .push(format!("Guest exit code: {exit_code:?}"));
    }

    // Close audio
    state.audio.lock().unwrap().close();

    // --- Smoke test validation ------------------------------------------------
    if let Some(smoke_seconds) = smoke_seconds {
        let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
        let frames = *state.rendered_frames.lock().unwrap();
        let fps = frames as f64 / elapsed;
        let audio = state.audio.lock().unwrap();
        let errs = state.errors.lock().unwrap().clone();

        println!("\n=== NATIVE HOST SMOKE TEST METRICS ===");
        println!("Rendered frames: {}", frames);
        println!("FPS: {:.2}", fps);
        println!("Audio backend opened: {}", state.audio_opened);
        println!("Audio buffers submitted: {}", audio.metrics.submitted);
        println!("Audio buffers completed: {}", audio.metrics.completed);
        println!("Audio buffers canceled: {}", audio.metrics.canceled);
        println!("Non-silent audio chunks: {}", audio.metrics.non_silent);
        println!("Guest exit code: {:?}", exit_code);
        println!(
            "Protocol/runtime errors: {}",
            errs.len() + audio.metrics.errors.len()
        );
        for e in errs.iter().chain(audio.metrics.errors.iter()) {
            println!("  - {}", e);
        }
        println!("======================================\n");

        let mut failures: Vec<&str> = Vec::new();
        let min_frames = (elapsed.min(smoke_seconds) * 15.0) as usize;
        if !state.audio_opened || audio.metrics.completed == 0 {
            failures.push("No completed audio playback");
        }
        if frames < min_frames {
            failures.push("Insufficient rendered frames");
        }
        if state.audio_opened && audio.metrics.submitted == 0 {
            failures.push("No audio buffers submitted (audio opened but silent)");
        }
        if state.audio_opened && audio.metrics.non_silent == 0 {
            failures.push("No non-silent audio submitted");
        }
        if !errs.is_empty() {
            failures.push("Protocol or runtime errors recorded");
        }
        if !audio.metrics.errors.is_empty() {
            failures.push("Audio API errors recorded");
        }
        // Guest exit unexpectedly (non-zero before timeout)
        if state.guest_exit_unexpected.load(Ordering::Relaxed) {
            failures.push("Guest exited with non-zero code during smoke window");
        }

        if failures.is_empty() {
            println!("[SMOKE TEST PASSED] Native Win32 host verified.");
        } else {
            println!("[SMOKE TEST FAILED]:");
            for f in &failures {
                println!("  * {}", f);
            }
            std::process::exit(1);
        }
    }
    if !state.errors.lock().unwrap().is_empty()
        || !state.audio.lock().unwrap().metrics.errors.is_empty()
    {
        std::process::exit(1);
    }
}
