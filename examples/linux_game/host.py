#!/usr/bin/env python3
"""
host.py - Windows Host Bridge (Display, Audio, Input) for Linux Game in LiteBox.

Architecture:
- Launches target/release/litebox_runner_linux_on_windows_userland.exe with target/linux-game/game.tar.
- Real-time display and audio loop:
    - Target 30 FPS driven by time.perf_counter() absolute deadlines to prevent timer creep.
    - Reads 'FRAM' packets (strictly 160x120 RGB24) via read_exact and displays using tk.PhotoImage(data=ppm, format="PPM").
    - Reads 'SND0' packets (strictly 735 PCM samples 22050Hz 16-bit mono).
    - WinMM waveOut with full types, checking MMRESULT on all API calls (Open, Prepare, Write, Reset, Unprepare, Close).
    - Precise audio tracking: only buffers confirmed finished via WHDR_DONE are counted as completed. Buffers unsubmitted or canceled by Reset are tracked as canceled.
    - Input state management: snapshot of desired keyboard state compared against sent state, preventing lost key-up events without relying on bounded queue overflow.
    - Releases keys on FocusOut.
    - Raises and deiconifies Tkinter window on startup without permanent topmost lock.
    - Optional --smoke-seconds N mode: runs real GUI and audio for N seconds, validates non-silent sound was submitted, all errors/exits, and returns non-zero exit code on failure.
"""

import os
import sys
import time
import struct
import argparse
import ctypes
from ctypes import wintypes
import subprocess
import threading
import queue
import tkinter as tk

GUEST_WIDTH = 160
GUEST_HEIGHT = 120
WINDOW_SCALE = 3  # 480 x 360 display
SAMPLE_RATE = 22050
EXPECTED_SAMPLES = 735
TARGET_FPS = 30.0
FRAME_INTERVAL = 1.0 / TARGET_FPS

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TAR_FILE = os.path.join(ROOT_DIR, "target", "linux-game", "game.tar")
RUNNER_BIN = os.path.join(ROOT_DIR, "target", "release", "litebox_runner_linux_on_windows_userland.exe")

DWORD_PTR = ctypes.c_size_t
MMRESULT = wintypes.UINT


def read_exact(stream, n):
    """Read exactly n bytes from a binary stream or raise EOFError."""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError(f"Unexpected EOF: expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


class WAVEFORMATEX(ctypes.Structure):
    _fields_ = [
        ("wFormatTag", wintypes.WORD),
        ("nChannels", wintypes.WORD),
        ("nSamplesPerSec", wintypes.DWORD),
        ("nAvgBytesPerSec", wintypes.DWORD),
        ("nBlockAlign", wintypes.WORD),
        ("wBitsPerSample", wintypes.WORD),
        ("cbSize", wintypes.WORD),
    ]


class WAVEHDR(ctypes.Structure):
    pass


WAVEHDR._fields_ = [
    ("lpData", ctypes.c_char_p),
    ("dwBufferLength", wintypes.DWORD),
    ("dwBytesRecorded", wintypes.DWORD),
    ("dwUser", ctypes.c_void_p),
    ("dwFlags", wintypes.DWORD),
    ("dwLoops", wintypes.DWORD),
    ("lpNext", ctypes.POINTER(WAVEHDR)),
    ("reserved", ctypes.c_void_p),
]

WAVE_FORMAT_PCM = 1
WHDR_DONE = 1


class WinMMAudioPlayer:
    def __init__(self, sample_rate=SAMPLE_RATE, max_queued_buffers=4):
        self.sample_rate = sample_rate
        self.max_queued_buffers = max_queued_buffers
        self.hWaveOut = wintypes.HANDLE()
        self.winmm = None
        self.available = False
        self.buffers = []  # list of (hdr, buf)
        self.lock = threading.Lock()
        self.submitted_buffers = 0
        self.completed_buffers = 0
        self.canceled_buffers = 0
        self.non_silent_submitted = 0
        self.errors = []

        try:
            self.winmm = ctypes.windll.winmm

            self.winmm.waveOutOpen.argtypes = [
                ctypes.POINTER(wintypes.HANDLE),
                wintypes.UINT,
                ctypes.POINTER(WAVEFORMATEX),
                DWORD_PTR,
                DWORD_PTR,
                wintypes.DWORD,
            ]
            self.winmm.waveOutOpen.restype = MMRESULT

            self.winmm.waveOutPrepareHeader.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(WAVEHDR),
                wintypes.UINT,
            ]
            self.winmm.waveOutPrepareHeader.restype = MMRESULT

            self.winmm.waveOutWrite.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(WAVEHDR),
                wintypes.UINT,
            ]
            self.winmm.waveOutWrite.restype = MMRESULT

            self.winmm.waveOutUnprepareHeader.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(WAVEHDR),
                wintypes.UINT,
            ]
            self.winmm.waveOutUnprepareHeader.restype = MMRESULT

            self.winmm.waveOutReset.argtypes = [wintypes.HANDLE]
            self.winmm.waveOutReset.restype = MMRESULT

            self.winmm.waveOutClose.argtypes = [wintypes.HANDLE]
            self.winmm.waveOutClose.restype = MMRESULT

            wfx = WAVEFORMATEX()
            wfx.wFormatTag = WAVE_FORMAT_PCM
            wfx.nChannels = 1
            wfx.nSamplesPerSec = self.sample_rate
            wfx.wBitsPerSample = 16
            wfx.nBlockAlign = 2
            wfx.nAvgBytesPerSec = self.sample_rate * 2
            wfx.cbSize = 0

            res = self.winmm.waveOutOpen(
                ctypes.byref(self.hWaveOut),
                0xFFFFFFFF,  # WAVE_MAPPER
                ctypes.byref(wfx),
                0, 0, 0
            )
            if res == 0:
                self.available = True
            else:
                err = f"waveOutOpen failed with MMRESULT {res}"
                self.errors.append(err)
                print(f"[host audio] {err}")
        except Exception as e:
            err = f"WinMM setup failed: {e}"
            self.errors.append(err)
            print(f"[host audio] {err}")

    def clean_done_buffers_locked(self):
        still_active = []
        for hdr, buf in self.buffers:
            if hdr.dwFlags & WHDR_DONE:
                res = self.winmm.waveOutUnprepareHeader(
                    self.hWaveOut, ctypes.byref(hdr), ctypes.sizeof(hdr)
                )
                if res != 0:
                    err = f"waveOutUnprepareHeader error: {res}"
                    self.errors.append(err)
                self.completed_buffers += 1
            else:
                still_active.append((hdr, buf))
        self.buffers = still_active

    def play_chunk(self, raw_pcm):
        if not self.available or not raw_pcm:
            return False

        # Measure non-silent PCM samples (16-bit signed)
        try:
            unpacked = struct.unpack(f"<{len(raw_pcm)//2}h", raw_pcm)
            if any(abs(s) > 100 for s in unpacked):
                self.non_silent_submitted += 1
        except Exception:
            pass

        with self.lock:
            self.clean_done_buffers_locked()

            if len(self.buffers) >= self.max_queued_buffers:
                self.canceled_buffers += 1
                return False

            buf = ctypes.create_string_buffer(raw_pcm)
            hdr = WAVEHDR()
            hdr.lpData = ctypes.cast(buf, ctypes.c_char_p)
            hdr.dwBufferLength = len(raw_pcm)
            hdr.dwFlags = 0

            res_prep = self.winmm.waveOutPrepareHeader(
                self.hWaveOut, ctypes.byref(hdr), ctypes.sizeof(hdr)
            )
            if res_prep != 0:
                err = f"waveOutPrepareHeader error: {res_prep}"
                self.errors.append(err)
                return False

            res_write = self.winmm.waveOutWrite(
                self.hWaveOut, ctypes.byref(hdr), ctypes.sizeof(hdr)
            )
            if res_write != 0:
                err = f"waveOutWrite error: {res_write}"
                self.errors.append(err)
                res_unprep = self.winmm.waveOutUnprepareHeader(
                    self.hWaveOut, ctypes.byref(hdr), ctypes.sizeof(hdr)
                )
                if res_unprep != 0:
                    self.errors.append(f"waveOutUnprepareHeader error on write rollback: {res_unprep}")
                return False

            self.submitted_buffers += 1
            self.buffers.append((hdr, buf))
            return True

    def close(self):
        with self.lock:
            if not self.available or not self.winmm:
                return
            try:
                # First clean buffers that finished naturally
                self.clean_done_buffers_locked()

                # Reset plays stop and marks pending buffers
                res_reset = self.winmm.waveOutReset(self.hWaveOut)
                if res_reset != 0:
                    self.errors.append(f"waveOutReset error: {res_reset}")

                # Unprepare any remaining buffers; count them strictly as canceled, NOT completed
                for hdr, buf in self.buffers:
                    res_unprep = self.winmm.waveOutUnprepareHeader(
                        self.hWaveOut, ctypes.byref(hdr), ctypes.sizeof(hdr)
                    )
                    if res_unprep != 0:
                        self.errors.append(f"waveOutUnprepareHeader error during close: {res_unprep}")
                    self.canceled_buffers += 1
                self.buffers.clear()

                res_close = self.winmm.waveOutClose(self.hWaveOut)
                if res_close != 0:
                    self.errors.append(f"waveOutClose error: {res_close}")
            except Exception as e:
                self.errors.append(f"Error during waveOut close: {e}")
            finally:
                self.available = False


class LinuxGameHost:
    def __init__(self, root, smoke_seconds=None):
        self.root = root
        self.smoke_seconds = smoke_seconds
        self.start_time = time.perf_counter()
        self.metrics = {
            "fps": 0.0,
            "rendered_frames": 0,
            "audio_buffers_submitted": 0,
            "audio_buffers_completed": 0,
            "audio_buffers_canceled": 0,
            "audio_non_silent_submitted": 0,
            "audio_backend_opened": False,
            "guest_exit_code": None,
            "errors": [],
        }

        self.root.title("Breakout - LiteBox")
        self.root.resizable(False, False)

        # Bring window to foreground on launch without keeping it topmost
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.attributes("-topmost", True)
            self.root.after_idle(lambda: self.root.attributes("-topmost", False))
            self.root.focus_force()
        except Exception:
            pass

        self.canvas_width = GUEST_WIDTH * WINDOW_SCALE
        self.canvas_height = GUEST_HEIGHT * WINDOW_SCALE

        self.info_label = tk.Label(
            root,
            text="Controles: Setas / A / D: Mover | Espaço: Reiniciar | ESC: Sair",
            font=("Segoe UI", 9),
            bg="#222222",
            fg="#dddddd",
            pady=4,
        )
        self.info_label.pack(fill=tk.X)

        self.canvas = tk.Canvas(
            root,
            width=self.canvas_width,
            height=self.canvas_height,
            bg="black",
            highlightthickness=0,
        )
        self.canvas.pack()

        # Audio backend
        self.audio = WinMMAudioPlayer(SAMPLE_RATE, max_queued_buffers=4)
        self.metrics["audio_backend_opened"] = self.audio.available

        # Process management
        self.proc = None
        self.running = True
        self.fatal_error = None
        self.frame_queue = queue.Queue(maxsize=2)

        # Desired vs sent key state tracking (prevents losing key-up)
        self.desired_keys = {1: False, 2: False, 3: False}
        self.sent_keys = {1: False, 2: False, 3: False}
        self.key_lock = threading.Lock()

        # Tkinter image
        self.scaled_photo = None
        self.canvas_img_id = self.canvas.create_image(0, 0, anchor=tk.NW)

        # Stderr buffer ring
        self.stderr_lines = []
        self.stderr_lock = threading.Lock()

        # Bindings
        self.root.bind("<KeyPress-Left>", lambda e: self.set_desired_key(1, True))
        self.root.bind("<KeyRelease-Left>", lambda e: self.set_desired_key(1, False))
        self.root.bind("<KeyPress-Right>", lambda e: self.set_desired_key(2, True))
        self.root.bind("<KeyRelease-Right>", lambda e: self.set_desired_key(2, False))
        self.root.bind("<KeyPress-a>", lambda e: self.set_desired_key(1, True))
        self.root.bind("<KeyRelease-a>", lambda e: self.set_desired_key(1, False))
        self.root.bind("<KeyPress-d>", lambda e: self.set_desired_key(2, True))
        self.root.bind("<KeyRelease-d>", lambda e: self.set_desired_key(2, False))
        self.root.bind("<KeyPress-space>", lambda e: self.set_desired_key(3, True))
        self.root.bind("<KeyRelease-space>", lambda e: self.set_desired_key(3, False))
        self.root.bind("<KeyPress-Escape>", lambda e: self.on_close())
        self.root.bind("<FocusOut>", lambda e: self.release_all_keys())
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.start_guest()

        # Threads
        self.reader_thread = threading.Thread(target=self._stdout_reader_loop, daemon=True)
        self.writer_thread = threading.Thread(target=self._stdin_writer_loop, daemon=True)
        self.stderr_thread = threading.Thread(target=self._stderr_reader_loop, daemon=True)
        self.reader_thread.start()
        self.writer_thread.start()
        self.stderr_thread.start()

        # Absolute deadline scheduler for precise ~30 FPS
        self.next_tick_deadline = time.perf_counter()
        self._schedule_next_frame()

    def set_desired_key(self, key_code, is_pressed):
        with self.key_lock:
            self.desired_keys[key_code] = is_pressed

    def release_all_keys(self):
        with self.key_lock:
            for k in self.desired_keys:
                self.desired_keys[k] = False

    def start_guest(self):
        if not os.path.exists(TAR_FILE):
            err = f"Error: {TAR_FILE} not found. Run build.py first!"
            self.metrics["errors"].append(err)
            print(f"[host] {err}")
            sys.exit(1)
        if not os.path.exists(RUNNER_BIN):
            err = f"Error: {RUNNER_BIN} not found. Run cargo build first!"
            self.metrics["errors"].append(err)
            print(f"[host] {err}")
            sys.exit(1)

        cmd = [RUNNER_BIN, "--initial-files", TAR_FILE, "/bin/breakout"]
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )

    def _stderr_reader_loop(self):
        if not self.proc or not self.proc.stderr:
            return
        stderr = self.proc.stderr
        while self.running:
            line = stderr.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                with self.stderr_lock:
                    if len(self.stderr_lines) >= 100:
                        self.stderr_lines.pop(0)
                    self.stderr_lines.append(text)
                print(f"[guest stderr] {text}")

    def _stdin_writer_loop(self):
        """Dedicated writer thread keeping stdin responsive and coalesced."""
        while self.running and self.proc and self.proc.poll() is None:
            packets = []

            # Synchronize key state differences
            with self.key_lock:
                for k, desired in self.desired_keys.items():
                    current = self.sent_keys.get(k, False)
                    if desired != current:
                        cmd = (b"KEYP" if desired else b"KEYR") + bytes([k])
                        packets.append(cmd)
                        self.sent_keys[k] = desired

            if packets:
                try:
                    for pkt in packets:
                        self.proc.stdin.write(pkt)
                    self.proc.stdin.flush()
                except Exception as e:
                    self.metrics["errors"].append(f"stdin writer key error: {e}")
                    break

            time.sleep(0.005)

    def _stdout_reader_loop(self):
        stdout = self.proc.stdout
        try:
            while self.running and self.proc and self.proc.poll() is None:
                magic = read_exact(stdout, 4)

                if magic == b"FRAM":
                    dim = read_exact(stdout, 4)
                    w, h = struct.unpack("<HH", dim)
                    if w != GUEST_WIDTH or h != GUEST_HEIGHT:
                        err = f"Invalid FRAM dimensions: expected {GUEST_WIDTH}x{GUEST_HEIGHT}, got {w}x{h}"
                        self.fatal_error = err
                        self.metrics["errors"].append(err)
                        print(f"[host protocol error] {err}")
                        break
                    rgb_data = read_exact(stdout, w * h * 3)
                    ppm = f"P6\n{w} {h}\n255\n".encode("ascii") + rgb_data
                    if self.frame_queue.full():
                        try:
                            self.frame_queue.get_nowait()
                        except queue.Empty:
                            pass
                    self.frame_queue.put(ppm)

                elif magic == b"SND0":
                    sz = read_exact(stdout, 2)
                    (num_samples,) = struct.unpack("<H", sz)
                    if num_samples != EXPECTED_SAMPLES:
                        err = f"Invalid SND0 samples: expected {EXPECTED_SAMPLES}, got {num_samples}"
                        self.fatal_error = err
                        self.metrics["errors"].append(err)
                        print(f"[host protocol error] {err}")
                        break
                    pcm_data = read_exact(stdout, num_samples * 2)
                    self.audio.play_chunk(pcm_data)

                else:
                    err = f"Unrecognized protocol tag: {magic!r}"
                    self.fatal_error = err
                    self.metrics["errors"].append(err)
                    print(f"[host protocol error] {err}")
                    break
        except EOFError as e:
            if self.running and (self.smoke_seconds is None or (time.perf_counter() - self.start_time < self.smoke_seconds)):
                self.fatal_error = f"Unexpected EOF: {e}"
                self.metrics["errors"].append(self.fatal_error)
        except Exception as e:
            self.fatal_error = f"stdout reader exception: {e}"
            self.metrics["errors"].append(self.fatal_error)
            print(f"[host reader error] {e}")

    def _schedule_next_frame(self):
        if not self.running:
            return

        now = time.perf_counter()
        # Compute delay until next deadline
        delay_s = self.next_tick_deadline - now
        if delay_s <= 0:
            delay_ms = 1
        else:
            delay_ms = max(1, int(delay_s * 1000.0))

        self.root.after(delay_ms, self._on_tick)

    def _on_tick(self):
        if not self.running:
            return

        if self.fatal_error:
            self.on_close()
            return

        now = time.perf_counter()
        if now >= self.next_tick_deadline:
            # Send TICK to advance guest
            if self.proc and self.proc.stdin and self.proc.poll() is None:
                try:
                    self.proc.stdin.write(b"TICK")
                    self.proc.stdin.flush()
                except Exception as e:
                    self.fatal_error = f"Failed to send TICK: {e}"
                    self.metrics["errors"].append(self.fatal_error)
                    self.on_close()
                    return

            # Advance deadline by exactly FRAME_INTERVAL
            self.next_tick_deadline += FRAME_INTERVAL
            # Coalesce if fallen too far behind (e.g. window dragged)
            if self.next_tick_deadline < now - 0.1:
                self.next_tick_deadline = now + FRAME_INTERVAL

        # Render available frame
        try:
            ppm_data = self.frame_queue.get_nowait()
            base_img = tk.PhotoImage(data=ppm_data, format="PPM")
            self.scaled_photo = base_img.zoom(WINDOW_SCALE, WINDOW_SCALE)
            self.canvas.itemconfig(self.canvas_img_id, image=self.scaled_photo)
            self.metrics["rendered_frames"] += 1
        except queue.Empty:
            pass
        except Exception as e:
            self.metrics["errors"].append(f"render error: {e}")

        # Check smoke duration
        elapsed = time.perf_counter() - self.start_time
        if self.smoke_seconds is not None and elapsed >= self.smoke_seconds:
            self.on_close()
            return

        # Check process status
        if self.proc and self.proc.poll() is not None:
            self.on_close()
            return

        self._schedule_next_frame()

    def on_close(self):
        if not self.running:
            return
        self.running = False

        # 1. Signal guest to exit
        if self.proc and self.proc.poll() is None:
            try:
                if self.proc.stdin:
                    self.proc.stdin.close()
            except Exception:
                pass

        # 2. Join reader threads before closing audio to avoid race conditions
        if threading.current_thread() != self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=1.0)

        # 3. Safely reset and close audio
        self.audio.close()

        # 4. Wait / terminate guest process
        if self.proc:
            try:
                self.proc.wait(timeout=1.5)
            except Exception:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=1.0)
                except Exception:
                    self.proc.kill()
            self.metrics["guest_exit_code"] = self.proc.returncode

        # Join remaining threads
        if threading.current_thread() != self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join(timeout=0.5)
        if threading.current_thread() != self.stderr_thread and self.stderr_thread.is_alive():
            self.stderr_thread.join(timeout=0.5)

        elapsed = max(0.001, time.perf_counter() - self.start_time)
        self.metrics["fps"] = round(self.metrics["rendered_frames"] / elapsed, 2)
        self.metrics["audio_buffers_submitted"] = self.audio.submitted_buffers
        self.metrics["audio_buffers_completed"] = self.audio.completed_buffers
        self.metrics["audio_buffers_canceled"] = self.audio.canceled_buffers
        self.metrics["audio_non_silent_submitted"] = self.audio.non_silent_submitted
        self.metrics["errors"].extend(self.audio.errors)

        try:
            self.root.destroy()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="LiteBox Linux Game Host (Breakout)")
    parser.add_argument(
        "--smoke-seconds",
        type=float,
        default=None,
        help="Run GUI smoke test for N seconds, then exit and print metrics",
    )
    args = parser.parse_args()

    root = tk.Tk()
    host = LinuxGameHost(root, smoke_seconds=args.smoke_seconds)
    root.mainloop()

    if args.smoke_seconds is not None:
        print("\n=== SMOKE TEST METRICS ===")
        print(f"Rendered frames: {host.metrics['rendered_frames']}")
        print(f"FPS: {host.metrics['fps']}")
        print(f"Audio backend opened: {host.metrics['audio_backend_opened']}")
        print(f"Audio buffers submitted: {host.metrics['audio_buffers_submitted']}")
        print(f"Audio buffers completed (playback finished): {host.metrics['audio_buffers_completed']}")
        print(f"Audio buffers canceled/discarded: {host.metrics['audio_buffers_canceled']}")
        print(f"Non-silent audio chunks submitted: {host.metrics['audio_non_silent_submitted']}")
        print(f"Guest exit code: {host.metrics['guest_exit_code']}")
        print(f"Errors encountered: {len(host.metrics['errors'])}")
        for err in host.metrics["errors"]:
            print(f"  - {err}")
        print("Note: Audio playback was submitted via winmm waveOut API; audible output depends on hardware host speakers.")
        print("==========================\n")

        # Strict validation requirements for smoke test success
        failures = []
        if not host.metrics["audio_backend_opened"]:
            failures.append("Audio backend failed to open")
        if host.metrics["rendered_frames"] < int(host.smoke_seconds * 15):
            failures.append(f"Insufficient rendered frames: {host.metrics['rendered_frames']}")
        if host.metrics["audio_buffers_completed"] == 0:
            failures.append("No audio buffers were confirmed completed")
        if host.metrics["audio_non_silent_submitted"] == 0:
            failures.append("No non-silent audio was synthesized/submitted")
        if host.metrics["guest_exit_code"] != 0:
            failures.append(f"Guest exited with non-zero code {host.metrics['guest_exit_code']}")
        if host.metrics["errors"]:
            failures.append(f"{len(host.metrics['errors'])} error(s) recorded during run")

        if failures:
            print("[SMOKE TEST FAILED]:")
            for f in failures:
                print(f"  * {f}")
            sys.exit(1)
        else:
            print("[SMOKE TEST PASSED] All GUI, frame rate, audio and guest criteria met.")


if __name__ == "__main__":
    main()
