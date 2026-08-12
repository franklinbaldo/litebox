# LiteBox on Windows without administrator access

This workflow builds from source in the current user profile. It does not
require WSL, an installer, or administrator privileges.

## Build the Windows-userland tools

Install Git and Rust for the current user, then use a Rust toolchain capable of
producing statically linked Windows binaries. For the GNU LLVM target:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnullvm --profile minimal
$previousLiteBoxRustFlags = $env:RUSTFLAGS
$env:RUSTFLAGS = '-C target-feature=+crt-static'
cargo +stable-x86_64-pc-windows-gnullvm build --locked --release `
  -p litebox_runner_linux_on_windows_userland `
  -p litebox_syscall_rewriter `
  -p litebox_packager
if ($null -eq $previousLiteBoxRustFlags) {
  Remove-Item Env:RUSTFLAGS
} else {
  $env:RUSTFLAGS = $previousLiteBoxRustFlags
}
```

`+crt-static` asks rustc to link the C runtime into the executable. The result
does not depend on a matching runtime DLL being installed on the client. It
does not make arbitrary dependencies static; each dependency still needs to
support static linking.

Build the generic launcher independently:

```powershell
cargo build --locked --release `
  --manifest-path .\tools\litebox-launcher\Cargo.toml
```

For regular use, install the `litebox` command from Git. `uv` invokes Maturin
and compiles the Rust launcher locally into an isolated tool environment:

```powershell
uv tool install git+https://github.com/franklinbaldo/litebox
litebox --help
```

If `litebox` is not found after installation, add uv's tool executable
directory to `PATH` once, then reopen the terminal:

```powershell
uv tool update-shell
```

Pin a tag or commit when installing for reproducibility instead of relying on
the moving default branch:

```powershell
uv tool install git+https://github.com/franklinbaldo/litebox@COMMIT
```

Use `uvx` when a temporary, non-persistent invocation is preferable:

```powershell
uvx --from git+https://github.com/franklinbaldo/litebox@COMMIT `
  litebox --help
```

The client still needs a working Rust compiler and linker because this Git
installation deliberately builds from source. Maturin applies
`-C target-feature=+crt-static` and refuses to build with a stale Cargo lockfile.
`uvx` packages the launcher only; the LiteBox runner and rootfs TAR remain
explicit arguments:

```powershell
litebox `
  --runner .\litebox-runner.exe `
  --initial-files .\rootfs.tar `
  --program /bin/sh -- -c "echo hello from LiteBox"
```

Clients can verify that two builds produced the same bytes when the compiler,
target, sources, lockfile, flags, and other build inputs are identical:

```powershell
Get-FileHash -Algorithm SHA256 `
  .\tools\litebox-launcher\target\release\litebox-launcher.exe
```

A SHA-256 digest verifies byte equality; by itself it does not prove who built
the executable or that its source is trustworthy. Publish the expected digest
through a trusted channel, preferably with a signed release or provenance.

## Run a TAR filesystem

The TAR must contain Linux paths and rewritten Linux executables. The launcher
is intentionally application-agnostic:

```powershell
.\tools\litebox-launcher\target\release\litebox-launcher.exe `
  --runner .\target\release\litebox_runner_linux_on_windows_userland.exe `
  --initial-files .\rootfs.tar `
  --env HOME=/tmp `
  --env LANG=C.UTF-8 `
  --program /bin/sh `
  -- -c "echo hello from LiteBox"
```

Inspect the filesystem from Windows with:

```powershell
tar -tvf .\rootfs.tar
```

The current Windows-userland runner loads one `--initial-files` TAR into an
in-memory filesystem. It does not expose a live host-directory mount, does not
write modified files back to the TAR, and does not accept several overlay TARs.
Folder synchronization therefore has to happen between runner sessions unless
those capabilities are added to the runner itself.

## Application example: Codex

Codex is not built into the launcher. Put a rewritten Linux Codex executable
at `/usr/local/bin/codex` in a compatible TAR and select it with
`--program /usr/local/bin/codex`. Pass only explicitly required credentials or
environment variables; do not forward the complete Windows environment.
