# LiteBox desktop transport

This standalone Rust crate defines the portable `desktop_fd_v1` framing layer.
It is intentionally independent of SDL, X11, Wayland, ALSA, OpenGL and Windows
APIs. A future host/guest adapter can supply dedicated LiteBox pipe endpoints.

The wire contract uses a 12-byte `LBDF` handshake followed by little-endian
length-prefixed messages. Message size is bounded before allocation; fragmented
reads are assembled; EOF at a frame boundary returns `None`, while EOF in a
header or body returns `Truncated`. `BoundedQueue` provides blocking and
non-blocking producer operations with explicit close/wakeup behavior.

This crate is a contract and integration foundation. It does not install FDs in
the Linux descriptor table, launch games, or provide any graphics/audio backend.

Validation:

```powershell
cargo test --locked --manifest-path tools/litebox_desktop_transport/Cargo.toml
cargo clippy --locked --all-targets --manifest-path tools/litebox_desktop_transport/Cargo.toml -- -D warnings
cargo run --locked --example desktop_transport_probe --manifest-path tools/litebox_desktop_transport/Cargo.toml
```
