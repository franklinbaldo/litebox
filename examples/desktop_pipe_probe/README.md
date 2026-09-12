# Dedicated guest pipe probe

Run `python examples/desktop_pipe_probe/run.py` on Windows x86_64. This reuses
the Breakout bootstrap: external Zig 0.13.0/musl compilation, LiteBox syscall
rewriter, USTAR packaging and the Windows userland platform. It does not run a
compiler inside LiteBox or implement SDL.

The Rust example installs two real Linux pipe descriptors via
`LoadedProgram::attach_host_input/output`, adapts their host ends to the existing
`litebox_desktop_transport::Framed` and exchanges an LBDF handshake and framed
echo with an ELF guest. The guest writes one byte at a time to exercise partial
reads. Both directions close with EOF, while guest stdout independently emits
`GUEST_STDOUT_OK`. The Python harness requires both success markers, exit zero,
and completion within 15 seconds (build commands have separate timeouts).

The test fixture asserts allocation of descriptors 3/4. Production integration
must convey the allocated descriptor numbers, rather than hard-code them.
Host endpoints own their pipe handles, close on drop, and have separate wait
states. Tests also cover EPIPE and descriptor allocation failure. Host operations
are blocking; UI integration still needs worker threads and explicit cancellation
when a guest stalls without closing. No busy polling is introduced.

Validated 2026-09-11: actual ELF handshake/echo/EOF and separate stdout passed;
three new shim tests passed. This is the byte transport foundation for reusing
the Breakout host with a shared SDL backend, not a graphics compatibility claim.
