# Windows vs LiteBox performance

This Windows-only harness compiles one dependency-free Rust workload for native
Windows and static Linux, rewrites the Linux system calls, creates a minimal
TAR, and runs paired samples in alternating order. It reports median, p95,
slowdown, and approximate harness/startup overhead.

The cases cover startup, CPU arithmetic, memory copying, temporary-file I/O,
and repeated metadata system calls. Each sample records both wall-clock time and
time measured inside the workload. Their difference includes process plumbing;
for LiteBox it additionally includes TAR loading and sandbox initialization.
An `fsync` compatibility probe is included and is expected to be reported as
unsupported on LiteBox versions where that syscall returns `ENOSYS`.
The `unlink_open` probe checks the inverse kind of difference: Linux commonly
allows unlinking an open file, while native Windows commonly rejects it. Probe
failures on either side remain in the raw JSON and are never scored as timings.

The `clock` and `threads` cases exercise host monotonic-time access and host CPU
parallelism. LiteBox does not expose arbitrary hardware merely because these
work: GPU, USB, camera, audio, raw block devices, performance counters, and
vendor accelerators require explicit host passthrough that this runner does not
currently advertise. Those capabilities are reported as unavailable/not
exposed rather than assigned misleading timing scores.

The `cpu_device` experiment is intentionally different: an x86-64 Linux ELF
executes `CPUID`, `RDTSC`, and `RDRAND` directly, even with `--hardware none`.
It demonstrates real host-CPU instruction access without a virtual device or a
Windows broker. This does not imply access to PCI, USB, or other peripherals,
which remain owned by Windows and require a device-specific backend.

## Run without admin or WSL

```powershell
rustup target add x86_64-unknown-linux-musl --toolchain stable-x86_64-pc-windows-gnullvm
powershell -ExecutionPolicy Bypass -File .\dev_bench\windows_litebox\run.ps1
```

Quick smoke test:

```powershell
powershell -ExecutionPolicy Bypass -File .\dev_bench\windows_litebox\run.ps1 `
    -Samples 3 -Warmups 1 -Units 4
```

Use `-LiteBox path\to\litebox.exe` to test another build. The TAR, raw JSON,
hashes, and Markdown report are written under the ignored `artifacts/` folder.

## Interpretation and limitations

- Startup is intentionally measured per invocation. Long-lived workloads should
  focus on the internal workload time as well as total wall time.
- The overhead value is an approximation: PowerShell capture and Windows process
  launch are present in both modes, while TAR parsing and LiteBox setup only
  occur in LiteBox mode.
- File I/O compares each environment's temporary filesystem. It is not a test of
  synchronization with a Windows directory or persistence between sessions.
- Static Linux and native Windows use different standard-library and OS
  implementations, so a ratio is an end-to-end result, not pure virtualization
  cost.
- Network is excluded because proxy, DNS, remote server, and connection reuse
  variance usually dominate the isolation overhead. Add it as a separate suite.
- Unsupported syscalls or semantics on either Windows or LiteBox are
  compatibility differences, not slow samples. Preserve the error output and
  report them separately instead of converting them into a performance score.
- Peak memory and CPU counters are not yet portable between a normal Windows
  process and LiteBox internals; this harness measures elapsed time only.

For reportable results, close CPU-heavy applications, use AC power and a stable
power profile, retain at least 15 samples, and publish the generated JSON.
