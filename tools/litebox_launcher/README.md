# Experimental native package launcher

New product code is Rust. Build with `cargo build --locked --release
--manifest-path tools/litebox_launcher/Cargo.toml` from the repository root.
The binary is in this crate's `target/release` directory.

Commands: `install <package-dir>`, `launch <game-id>`, `uninstall <game-id>`.
Use `--root <absolute-test-directory>` to keep installation and shortcuts outside
the real user profile. Default installation uses LocalAppData/LiteBox and the
user's Start Menu Programs/LiteBox directory. No administrator access is needed.

Multiple game IDs have independent state, icons, shortcuts, versions and reserved
data directories. Shortcuts target the stable installed launcher and pass the ID;
their AppUserModelID is `LiteBox.Game.<id>`. Removal preserves host data, and refuses
to remove an active package. Updates pin active sessions to their existing version.

## Provisional package format

`package.json` contains `schema_version: 1`, `id`, `name`, `version`, `runtime`,
`content`, `icon`, and `files`. Each file has a flat relative `path`, a lowercase
SHA256 and an exact `size`. Runtime contains `profile`, `required_features`,
`host`, and `runner`; artifact roles reference verified files. IDs are lowercase
alphanumeric segments separated by hyphens. Case-insensitive filename collisions,
reserved Windows names, path traversal and reparse points are rejected.

Only the `demo_stdio_v1` launch adapter currently exists. Its capabilities are
`rgb24_160x120`, `pcm_s16_mono_22050`, and `keyboard_demo`. Unsupported profiles or
features fail before installation; accepting multiple IDs does not make the demo
host compatible with arbitrary games. Package executables must come from a trusted
source: integrity hashes alone are not authenticity checks or a host sandbox.

This provisional format is not the proposed `docs/desktop/game-package.schema.json`.
See `docs/desktop/general-compatibility.md` for consolidation and runtime work.
Guest entrypoints, general desktop transport, shared runtime distribution, guest
save mounts and registration in Windows Installed Apps are still outstanding.
Interrupted pre-journal staging is preserved for inspection. Uninstall also
preserves packages with unknown or damaged contents instead of deleting blindly.

## Validation

Run `cargo test --locked --release --manifest-path tools/litebox_launcher/Cargo.toml`
and `cargo clippy --locked --release --all-targets --manifest-path
tools/litebox_launcher/Cargo.toml -- -D warnings`.

`python tools/desktop_acceptance/package_isolation.py` tests two inert packages,
paths with spaces, independent shortcuts/state, update, interrupted-update
rollback, rejected unsupported runtime, hashes, traversal and preservation of a
host data sentinel. It does not execute games or prove guest save persistence.
