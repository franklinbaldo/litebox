# LiteBox

> A security-focused library OS

> [!NOTE]  
> This project is currently actively evolving and improving. While we are
> working toward a stable release, some APIs and interfaces may change as the
> design continues to mature. You are welcome to explore and experiment, but if
> you need long-term stability, it may be best to wait for a stable release, or
> be prepared to adapt to updates along the way.

LiteBox is a sandboxing library OS that drastically cuts down the interface to the host, thereby reducing attack surface.  It focuses on easy interop of various "North" shims and "South" platforms.  LiteBox is designed for usage in both kernel and non-kernel scenarios.

LiteBox exposes a Rust-y [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-inspired "North" interface when it is provided a `Platform` interface at its "South".  These interfaces allow for a wide variety of use-cases, easily allowing for connection between any of the North--South pairs.

Example use cases include:
- Running unmodified Linux programs on Windows
- Sandboxing Linux applications on Linux
- Run programs on top of SEV SNP
- Running OP-TEE programs on Linux
- Running on LVBS

![LiteBox and related projects](./.figures/litebox.svg)

## Contributing

See the following files for details:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [SECURITY.md](./SECURITY.md)
- [SUPPORT.md](./SUPPORT.md)

## Windows without administrator access

The fork includes a small source-distributed Rust launcher and a reproducible
workflow for running TAR-based Linux filesystems with the Windows-userland
runner. Install its `litebox` command directly from Git with
[uv](https://docs.astral.sh/uv/):

```powershell
uv tool install git+https://github.com/franklinbaldo/litebox
```

The installation compiles and installs the launcher, Windows-userland runner,
syscall rewriter, and packager directly from the pinned repository source. Run
`litebox --help` to see its Docker-like command interface. Run any compatible
TAR-backed Linux program with:

```powershell
litebox run --env HOME=/tmp .\rootfs.tar /bin/sh -c "echo hello from LiteBox"
```

Other common operations follow the same command hierarchy:

```powershell
litebox image build --oci docker.io/library/alpine:3.22 --output .\alpine.tar
litebox image inspect .\alpine.tar
litebox rewrite .\program-linux --output .\program-linux.hooked
litebox doctor
litebox version
```

To keep a TAR encrypted at rest, create a passphrase-protected `age` file and
select it when starting LiteBox:

```powershell
litebox image encrypt .\rootfs.tar --output .\rootfs.tar.age
litebox run .\rootfs.tar.age /bin/sh
```

Both commands prompt for the passphrase without echoing it. The launcher
decrypts to a temporary TAR only for the runner session and removes that file
when the process exits normally.

The pre-0.3 `--initial-files`/`--program` syntax remains accepted with a
deprecation warning so existing scripts can migrate incrementally.

The client compiles the tools from source during installation and must have a
working Rust compiler and linker. The rootfs TAR remains an explicit input.
See [docs/windows-no-admin.md](./docs/windows-no-admin.md) for
the full no-admin build, SHA-256, and filesystem workflow.

## License

MIT License.  See [./LICENSE](./LICENSE) for details.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
