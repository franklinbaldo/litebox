# SDL2 Linux video on Windows through LiteBox

This integration fixture uses genuine SDL2 2.30.12 (upstream commit
`8236e01a9f758d15927624925c6043f84d8a261f`). The application draws with ordinary
SDL window/surface APIs. A marked derivative of SDL's dummy driver implements
pixel transmission; it is selected as `SDL_VIDEODRIVER=litebox`. The Windows
receiver is Rust and reuses the Breakout host's top-down BGRA/GDI approach.

## Build and run (Windows x86_64)

Install the usual repository Rust toolchain, Python/uv, CMake and Ninja. Build
the existing Windows runner and rewriter first. From the repository root:

```powershell
cargo build --locked -p litebox_runner_linux_on_windows_userland -p litebox_syscall_rewriter
uv run --with ziglang==0.13.0 python examples/sdl_probe/build_video.py
python examples/desktop_pipe_probe/run_video.py target/sdl-bootstrap/video-probe.tar
```

Compilation is external using Zig/musl, as for Breakout. No compiler executes
inside LiteBox. `LITEBOX_TOOLS_DIR` optionally selects existing runner/rewriter
binaries. `SDL_BOOTSTRAP_DIR` optionally selects an existing SDL source/build
cache. The source commit and patch applicability are checked. Source and binary
hashes are recorded in `manifest_video.json`; generated artifacts are not tracked.

## What is verified

On 2026-09-11 the real guest produced red, green, and blue 160x120 frames, each
with a centered white rectangle. The receiver verified the expected corner and
center pixels of every frame, presented all three with successful GDI returns,
observed pipe EOF, and finished with guest exit 0. The final received RGB image
was also inspected. The desktop screenshot API failed to activate/capture the
window, so a screenshot of actual on-screen composition was **not** verified.

The first run exposed missing backend channel cleanup: all three frames arrived
and the guest exited, but the host waited indefinitely for EOF. The supervisor
added channel closure in SDL video teardown. The corrected full run passed.
This does not establish generic descriptor cleanup on abnormal guest exit.

The harness saves stdout/stderr and the last received frame under
`target/sdl-video-validation`, validates the success marker and exit code, and
kills the process on timeout. `--hold-seconds 30` keeps the final frame visible
briefly for manual inspection. A parser test rejects wrong size/tag/dimensions.

## Scope

This is a **video and synthetic keyboard fixture**, not a playable game or general SDL backend.
Only one window, one session, 160x120 RGB24 and SDL surface presentation are
implemented. Native Windows input, audio, resize, multiple windows, SDL_Renderer coverage,
OpenGL, persistence and abnormal-exit cleanup still need integration/testing.
The backend's fixed descriptors 3/4 are fixture assumptions; production code
must receive allocated descriptors explicitly. The guest driver patch retains
upstream C and its license; it is not a reimplementation of SDL in Rust.

The existing LBDF v1 handshake and length framing are used, with FRAM/dimensions/
RGB payload adapted from Breakout. The older LBG1 sketch is not the wire format
of this test. The bounded Rust receiver uses a one-frame queue and worker threads;
the prototype driver uses synchronous writes and a process-local handshake.

## SDL keyboard verification

```powershell
uv run --with ziglang==0.13.0 python examples/sdl_probe/build_input.py
python examples/desktop_pipe_probe/run_video.py target/sdl-bootstrap/input-probe.tar --input-probe
python examples/desktop_pipe_probe/run_video.py target/sdl-bootstrap/input-probe.tar --input-probe --focus-release
```

Both variants passed on 2026-09-11 with guest exit 0, verified red/green/blue
frames, and SDL_KEYDOWN_RIGHT_OK / SDL_KEYUP_RIGHT_OK markers. The host sends
synthetic framed KEY0 events after receiving each frame. The application uses
SDL_PollEvent and also checks SDL_GetKeyboardState. In the second variant FOC0
releases held keys through SDL_ResetKeyboard. This verifies the transport and
SDL event/state path; it does not yet connect physical Windows keyboard events.

Input records have an eight-byte body: KEY0, little-endian u16 SDL scancode,
one-byte pressed flag and zero reserved byte; or FOC0 and four zero bytes.
The driver incrementally reads bounded records without waiting for incomplete
messages, validates them, and resets keys on EOF or invalid input. Its static
parser state is limited to a single SDL initialization per process.

## SDL audio verification

```powershell
uv run --with ziglang==0.13.0 python examples/sdl_probe/build_audio.py
cargo build --locked -p litebox_runner_linux_on_windows_userland --example sdl_audio_probe
python examples/sdl_probe/run_audio.py
```

The SDL audio callback generates S16LE mono PCM at 22050 Hz. Dedicated guest
descriptors 5/6 carry framed AUD0 buffers and ACK0 completion acknowledgements.
The Rust host reuses the Breakout WinMM module and acknowledges each buffer only
after completion. On 2026-09-11 the independent supervised run received, submitted
and completed nine buffers (eight non-silent), with no errors or cancellations,
including device closure, and guest exit 0. Positive and negative samples were
verified. This proves WinMM completion, not an acoustic recording.

The harness enforces a ten-second timeout and keeps its logs and JSON report in
ignored `target/sdl-audio-validation`. Seven parser tests cover malformed messages.
Audio and video/input are still separate fixtures; a combined interactive SDL
application and native Windows keyboard routing remain future work.
