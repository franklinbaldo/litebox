#!/usr/bin/env python3
"""
test_headless.py - Comprehensive End-to-End Headless Verification.

Verifies:
1. LiteBox runner boots the Linux game ELF inside Windows Userland without crashing.
2. Initial frame (FRAM) packet is received with expected dimensions (strictly 160x120).
3. Initial sound (SND0) packet is received with strictly 735 PCM samples.
4. Sending TICK commands advances game physics and produces varying frame data (ball movement).
5. User input verification: measures paddle pixels at the exact same tick with vs without input.
6. Audio packets during collisions contain non-silent synthesized PCM samples.
7. Clean guest exit upon closing pipe.
8. Enforces strict timeouts and guaranteed cleanup on EVERY instance (including helpers).
"""

import os
import sys
import time
import struct
import subprocess
import threading

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TAR_FILE = os.path.join(ROOT_DIR, "target", "linux-game", "game.tar")
RUNNER_BIN = os.path.join(ROOT_DIR, "target", "release", "litebox_runner_linux_on_windows_userland.exe")

GUEST_WIDTH = 160
GUEST_HEIGHT = 120
EXPECTED_SAMPLES = 735
INSTANCE_TIMEOUT_SECONDS = 15.0

PADDLE_Y = 120 - 12  # 108
PADDLE_COLOR = (70, 160, 240)


def read_exact(stream, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError(f"Unexpected EOF: expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def read_packet(stdout):
    magic = read_exact(stdout, 4)
    if magic == b"FRAM":
        dim = read_exact(stdout, 4)
        w, h = struct.unpack("<HH", dim)
        if w != GUEST_WIDTH or h != GUEST_HEIGHT:
            raise ValueError(f"Strict FRAM dimensions mismatch: expected {GUEST_WIDTH}x{GUEST_HEIGHT}, got {w}x{h}")
        rgb = read_exact(stdout, w * h * 3)
        return "FRAM", (w, h, rgb)
    elif magic == b"SND0":
        sz = read_exact(stdout, 2)
        (num_samples,) = struct.unpack("<H", sz)
        if num_samples != EXPECTED_SAMPLES:
            raise ValueError(f"Strict SND0 samples mismatch: expected {EXPECTED_SAMPLES}, got {num_samples}")
        pcm = read_exact(stdout, num_samples * 2)
        return "SND0", (num_samples, pcm)
    else:
        raise ValueError(f"Unknown packet header: {magic!r}")


def get_paddle_center_x(rgb_bytes):
    """Find the horizontal center of the paddle pixels on line PADDLE_Y."""
    row_start = PADDLE_Y * GUEST_WIDTH * 3
    row_end = row_start + GUEST_WIDTH * 3
    row_pixels = rgb_bytes[row_start:row_end]

    xs = []
    for x in range(GUEST_WIDTH):
        r = row_pixels[x * 3]
        g = row_pixels[x * 3 + 1]
        b = row_pixels[x * 3 + 2]
        if (r, g, b) == PADDLE_COLOR:
            xs.append(x)

    if not xs:
        return None
    return sum(xs) / len(xs)


def drain_stderr(proc, lines_accumulator):
    try:
        for line in iter(proc.stderr.readline, b""):
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                if len(lines_accumulator) < 50:
                    lines_accumulator.append(text)
    except Exception:
        pass


def run_instance_with_timeout(num_ticks, input_commands=None, timeout_sec=INSTANCE_TIMEOUT_SECONDS):
    """Run an instance protected by a strict watchdog timer, returning the final frame RGB."""
    cmd = [RUNNER_BIN, "--initial-files", TAR_FILE, "/bin/breakout"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0
    )
    stderr_lines = []
    t_err = threading.Thread(target=drain_stderr, args=(proc, stderr_lines), daemon=True)
    t_err.start()

    timed_out = False
    def kill_proc():
        nonlocal timed_out
        timed_out = True
        try:
            proc.kill()
        except Exception:
            pass

    timer = threading.Timer(timeout_sec, kill_proc)
    timer.daemon = True
    timer.start()

    try:
        p_type, p_data = read_packet(proc.stdout)
        assert p_type == "FRAM"
        a_type, a_data = read_packet(proc.stdout)
        assert a_type == "SND0"

        last_rgb = p_data[2]

        if input_commands:
            for c in input_commands:
                proc.stdin.write(c)
                proc.stdin.flush()

        for _ in range(num_ticks):
            proc.stdin.write(b"TICK")
            proc.stdin.flush()
            p_type, p_data = read_packet(proc.stdout)
            a_type, a_data = read_packet(proc.stdout)
            last_rgb = p_data[2]

        proc.stdin.close()
        proc.wait(timeout=2)
        return last_rgb
    except Exception as e:
        if timed_out:
            raise TimeoutError(f"Instance timed out after {timeout_sec}s") from e
        raise
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass


def run_headless_test():
    print("==================================================")
    print("  LiteBox Linux Game Headless End-to-End Test")
    print("==================================================")

    if not os.path.exists(TAR_FILE):
        print(f"FAILED: {TAR_FILE} not found. Run build.py first.")
        sys.exit(1)
    if not os.path.exists(RUNNER_BIN):
        print(f"FAILED: {RUNNER_BIN} not found.")
        sys.exit(1)

    # 1. Test Input Displacements: measure paddle pixels at the exact same tick with and without input
    print("[*] Testing user input: comparing paddle pixel positions at identical tick count (tick 10)...")
    frame_neutral = run_instance_with_timeout(10, input_commands=[])
    center_neutral = get_paddle_center_x(frame_neutral)
    assert center_neutral is not None, "Paddle not found in neutral frame!"

    frame_left = run_instance_with_timeout(10, input_commands=[b"KEYP\x01"])
    center_left = get_paddle_center_x(frame_left)
    assert center_left is not None, "Paddle not found in left input frame!"

    frame_right = run_instance_with_timeout(10, input_commands=[b"KEYP\x02"])
    center_right = get_paddle_center_x(frame_right)
    assert center_right is not None, "Paddle not found in right input frame!"

    assert center_left < center_neutral, f"Expected paddle to move left: neutral={center_neutral}, left={center_left}"
    assert center_right > center_neutral, f"Expected paddle to move right: neutral={center_neutral}, right={center_right}"
    print(f"[PASS] Paddle position at tick 10: Left={center_left:.1f}px < Neutral={center_neutral:.1f}px < Right={center_right:.1f}px")

    # 2. Main End-to-End Session with Watchdog Timer
    cmd = [RUNNER_BIN, "--initial-files", TAR_FILE, "/bin/breakout"]
    print(f"[*] Spawning LiteBox runner: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0
    )

    stderr_lines = []
    t_err = threading.Thread(target=drain_stderr, args=(proc, stderr_lines), daemon=True)
    t_err.start()

    timed_out = False
    def on_timeout():
        nonlocal timed_out
        timed_out = True
        print(f"\n[!] ERROR: Test instance timeout ({INSTANCE_TIMEOUT_SECONDS}s) exceeded! Terminating child...")
        if proc and proc.poll() is None:
            proc.kill()

    watchdog = threading.Timer(INSTANCE_TIMEOUT_SECONDS, on_timeout)
    watchdog.daemon = True
    watchdog.start()

    try:
        # Initial Frame Check
        pkt_type, pkt_data = read_packet(proc.stdout)
        assert pkt_type == "FRAM", f"Expected FRAM packet, got {pkt_type}"
        w, h, rgb0 = pkt_data
        assert w == GUEST_WIDTH and h == GUEST_HEIGHT, f"Unexpected dimensions: {w}x{h}"
        assert len(rgb0) == GUEST_WIDTH * GUEST_HEIGHT * 3, "Incomplete frame buffer"
        print(f"[PASS] Received initial frame: {w}x{h} ({len(rgb0)} bytes)")

        # Initial Audio Check
        pkt_type, pkt_data = read_packet(proc.stdout)
        assert pkt_type == "SND0", f"Expected SND0 packet, got {pkt_type}"
        samples, pcm0 = pkt_data
        assert samples == EXPECTED_SAMPLES, f"Unexpected sample count: {samples}"
        assert len(pcm0) == EXPECTED_SAMPLES * 2, "Incomplete PCM data"
        print(f"[PASS] Received initial audio: {samples} samples ({len(pcm0)} bytes)")

        # Verify physics progression
        print("[*] Simulating 15 game ticks to verify ball movement...")
        frames = [rgb0]
        for tick in range(15):
            proc.stdin.write(b"TICK")
            proc.stdin.flush()

            p_type, p_data = read_packet(proc.stdout)
            assert p_type == "FRAM", f"Tick {tick}: expected FRAM"
            frames.append(p_data[2])

            a_type, a_data = read_packet(proc.stdout)
            assert a_type == "SND0", f"Tick {tick}: expected SND0"

        diff_count = sum(1 for a, b in zip(frames[0], frames[15]) if a != b)
        assert diff_count > 0, "Frames are static! Ball is not moving."
        print(f"[PASS] Physics verified: Frame 15 has {diff_count} differing color bytes from initial frame.")

        # Audio synthesis check
        print("[*] Running game loop until dynamic non-silent collision audio is generated...")
        non_silent_detected = False
        max_amplitude = 0

        for tick in range(120):
            proc.stdin.write(b"TICK")
            proc.stdin.flush()
            p_type, p_data = read_packet(proc.stdout)
            a_type, a_data = read_packet(proc.stdout)

            num_samples, pcm_bytes = a_data
            unpacked = struct.unpack(f"<{num_samples}h", pcm_bytes)
            peak = max(abs(s) for s in unpacked)
            if peak > max_amplitude:
                max_amplitude = peak
            if peak > 1000:
                non_silent_detected = True
                print(f"[PASS] Collision sound detected at tick {tick}: peak PCM amplitude = {peak}")
                break

        assert non_silent_detected, f"No non-silent audio generated (max peak = {max_amplitude})"
        print(f"[PASS] Audio synthesis verified: Guest produced genuine synthesized waveforms.")

        # Graceful exit
        proc.stdin.close()
        proc.wait(timeout=3)
        assert proc.returncode == 0, f"Guest exited with non-zero code: {proc.returncode}"
        print(f"[PASS] Graceful exit verified (return code {proc.returncode}).")

        print("==================================================")
        print("  ALL HEADLESS VERIFICATION CHECKS PASSED (100%)")
        print("==================================================")

    except Exception as e:
        if timed_out:
            print(f"[FAIL] Test timed out after {INSTANCE_TIMEOUT_SECONDS}s!")
        else:
            print(f"[FAIL] Error occurred: {e}")
        if stderr_lines:
            print(f"[stderr output from guest]:\n" + "\n".join(stderr_lines))
        raise
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass


if __name__ == "__main__":
    run_headless_test()
