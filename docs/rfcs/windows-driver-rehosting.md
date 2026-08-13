# RFC: Windows driver rehosting experiments

Status: proposal

## Summary

Explore whether selected Windows driver binaries can be loaded in a constrained
user-mode environment, given synthetic NT kernel objects and requests, so that
LiteBox can observe and reuse their output without installing the driver in the
Windows kernel.

This is driver *rehosting*, not driver installation or hardware passthrough. A
`.sys` file remains untrusted native code. The initial work must not load a
driver into the host kernel, forward arbitrary IOCTLs, map physical memory, or
touch real devices.

## Motivation

The Windows-userland runner can already broker typed host capabilities. A
rehosted driver could potentially contribute protocol parsing,
device-independent algorithms, and IOCTL response generation while LiteBox
controls every external effect. It could also provide a contained research
environment for understanding small drivers before implementing a typed
Windows backend.

## Proposed architecture

```text
Windows driver.sys
  -> constrained PE loader and relocator
  -> minimal emulated NT kernel ABI
  -> synthetic DRIVER_OBJECT / DEVICE_OBJECT / IRP
  -> captured status, output buffer, logs, and attempted host operations
  -> optional typed LiteBox capability backend (future work)
```

All imports must resolve through an explicit registry. Unknown APIs fail closed.
APIs that could access the host are represented as trapped operations; they are
recorded or simulated, never executed implicitly.

## Staged experiment

1. Inspect a PE `.sys` without executing it: architecture, imports, sections,
   relocations, entry point, and declared metadata.
2. Load a purpose-built toy driver with no hardware dependencies.
3. Emulate a minimal ABI sufficient for `DriverEntry`, allocation, logging,
   device creation, dispatch registration, and completion of a buffered IOCTL.
4. Construct a synthetic IRP and capture its NTSTATUS and output buffer.
5. Run the rehost in a separate restricted process with time, memory, and
   operation limits.
6. Only after an explicit security review, investigate mapping trapped driver
   operations to typed capability backends. Arbitrary host IOCTL forwarding is
   out of scope.

## Security boundary

- Rehosted `.sys` code is untrusted native code and must not run inside the main
  launcher process in the production design.
- No administrator rights, kernel driver installation, SCM registration,
  physical memory mapping, port I/O, DMA, interrupts, or arbitrary device
  handles are part of the initial experiment.
- `--hardware none` must imply that every attempted external effect is rejected
  or simulated.
- Inputs and outputs are bounded and copied; guest pointers are never passed to
  a Windows driver or API.
- Crashes, timeouts, unsupported imports, and trapped operations are expected
  experiment results, not reasons to weaken validation.
- Testing third-party drivers must respect their licenses and should happen in
  disposable VMs when the experiment progresses beyond our toy binary.

## Non-goals

- Running arbitrary production drivers correctly.
- Reimplementing the complete NT kernel, WDM, KMDF, PnP, or power manager.
- Allowing a Linux application to issue arbitrary Windows IOCTLs.
- Claiming that driver rehosting gives direct access to physical hardware.
- Replacing typed brokers such as Winsock, WASAPI, Media Foundation, or GPU APIs.

## Success criteria for the toy

- A driver built specifically for the experiment is parsed and relocated.
- `DriverEntry` executes with only allowlisted imports.
- The driver registers one synthetic device and buffered IOCTL handler.
- A synthetic request returns a deterministic output buffer.
- An unsupported import and attempted host operation both fail closed.
- A crash or infinite loop cannot terminate or indefinitely block the launcher.

## Open questions

- Which PE loader or existing permissively licensed implementation should be
  reused?
- Should the first execution sandbox be a subprocess, a WebAssembly translation,
  or another isolation boundary?
- Which NT ABI version and calling conventions should the toy freeze?
- How should trapped operations be represented so future typed brokers can
  consume them without exposing arbitrary host calls?
- What disclosure workflow should be followed if analysis of a third-party
  driver reveals a likely vulnerability?
