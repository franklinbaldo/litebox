# Native Windows control host

Rust implementation of the existing Breakout demo's fixed stdio protocol, using
Win32/GDI for video and WinMM for audio. This is a performance and lifecycle
control, not a general Linux graphics backend. It does not implement SDL, X11,
Wayland, ALSA or OpenGL. See `docs/desktop/general-compatibility.md`.

From the repository root:

```powershell
cargo build --locked --release --manifest-path tools/litebox_desktop_host/Cargo.toml
tools/litebox_desktop_host/target/release/litebox_desktop_host.exe --runner target/release/litebox_runner_linux_on_windows_userland.exe --tar target/linux-game/game.tar --smoke-seconds 5
```

Optional `--icon <file.ico>` and `--app-id <id>` integrate window identity with
the launcher. Left/right move the paddle; Space restarts. Focus loss releases
keys. Runner and archive paths are explicit. Closing the window closes input,
drains output and gives the guest two seconds to exit before forced termination.
Protocol errors, failed audio operations and nonzero guest exit cause failure.

The parser limits packets before reading their bodies. A separate writer thread
keeps guest input off the UI thread; input and audio queues are bounded. Audio
storage stays alive until WinMM releases it. Smoke output distinguishes completed
audio buffers and nonzero samples; neither establishes what a person hears.

## Local validation, 2026-09-11

Three protocol unit tests cover fragmented input, invalid sizes/tags and truncated
EOF. Clippy runs with warnings denied. `tools/desktop_acceptance/native_input_probe.py`
confirmed left/right movement and stopping on focus loss. The original AGY host
failed that focus test; the integrated host was corrected. Failure fixtures cover
nonzero exit, truncated output and malformed output followed by a hung process.

A single sequential comparison used the same demo and measured the process tree
for 60 seconds during 62-second smoke sessions, without input:

| Host | FPS over session | CPU, one-core equivalent | Peak summed working set |
|---|---:|---:|---:|
| Python | 29.97 | 17.86% | 43.3 MiB |
| Rust | 29.99 | 2.55% | 30.3 MiB |

Both guests exited zero. This includes the idle/game-over trajectory; it is not
a sustained gameplay benchmark or evidence about SDL games. Working-set sums can
count shared pages twice. Raw observations are in local `target/desktop-acceptance`.
Windows loopback capture was unavailable on this machine, so current native audio
was checked through submitted/completed buffer metrics, not an audibility test.
The user's earlier confirmation of sound applied to the previous demo host.
