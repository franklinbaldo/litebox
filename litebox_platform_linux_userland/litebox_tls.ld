/* Copyright (c) Microsoft Corporation. */
/* Licensed under the MIT license. */

/*
 * Forces `.tdata.litebox_tls` to the front of the static TLS block on AArch64.
 *
 * The transition assembly in `litebox_platform_linux_userland` addresses its
 * TLS control block with literal offsets from `TPIDR_EL0` (see `tls_offset`),
 * because `syscall_callback` is entered with only `x16` free and cannot afford
 * the second scratch register a `#:tprel_g1:`/`#:tprel_g0_nc:` pair needs. In
 * particular `guest_tpidr` must land at exactly +16: that offset is the
 * `litebox_syscall_rewriter` ABI (`arm64::GUEST_TPIDR_OFFSET`), baked into the
 * gates the rewriter emits into the guest binary.
 *
 * AArch64 uses TLS variant 1, so the static block starts at
 * `round_up(16, align(PT_TLS))` and `guest_tpidr` is at +16 only if
 * `.tdata.litebox_tls` is the very first input section in `.tdata`. The default
 * linker script matches `*(.tdata .tdata.* .gnu.linkonce.td.*)` with no
 * sorting, so the order is input-object order -- i.e. whichever rlib the
 * linker happened to see first. That is not something the source can control:
 * linking `tracing_subscriber` (as `litebox_runner_linux_userland` does) puts
 * two 40-byte thread-locals ahead of the block and moves `guest_tpidr` to +96.
 *
 * Respelling the `.tdata` rule with our input section first fixes the order
 * without otherwise perturbing the layout: this is `INSERT`ed as a fragment, so
 * the rest of the default script still applies, and the resulting PT_TLS is
 * byte-for-byte the same size as before.
 *
 * This crate cannot apply the fragment on its own behalf: a Cargo build script
 * only contributes link arguments to its own package's artifacts, and this
 * package is a library with neither a bin nor a test target. So every crate
 * that links this one and produces a binary that runs guest code must pass
 * `-Wl,-T,<this file>` itself; see `litebox_runner_linux_userland/build.rs`.
 * `assert_tls_layout()` re-checks the result at `LinuxUserland::new`, so a link
 * that misses this fragment aborts with a legible message rather than
 * corrupting host TLS or the guest thread pointer.
 */
SECTIONS
{
  .tdata : { *(.tdata.litebox_tls) *(.tdata .tdata.* .gnu.linkonce.td.*) }
} INSERT BEFORE .tbss;
