# HEKI/HVCI algorithms, host-testable via the `HekiEnforcer` port

> [!WARNING]
> This crate is work in progress.

This crate owns the HEKI/HVCI algorithms (guest-module validation, kexec
validation, kdata loading, memory protection, text patching, end-of-boot,
ringbuffer/platform-root-key setup, certificate parsing, and the memory-
integrity checks). The algorithms are generic over the `HekiEnforcer` port,
which abstracts the platform's enforcement primitives (VTL0 reads, transactional
frame protection, text patching, ringbuffer and platform-root-key installation).

Because the algorithms depend only on the port and not on any real platform,
they are testable on the host: a `MockEnforcer` backs the unit tests, so
HEKI/HVCI can be exercised with `cargo test -p litebox_heki` without an LVBS
platform. `litebox_platform_lvbs` provides the production adapter
(`PlatformHekiEnforcer`), and `litebox_runner_lvbs` is the composition root that
wires the two together.
