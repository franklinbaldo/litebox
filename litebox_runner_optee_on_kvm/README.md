# A LiteBox Runner for OP-TEE on KVM/QEMU

> [!WARNING]
> This crate is work in progress, and it installs a **development platform root
> key with no security value** (see [Platform root key](#platform-root-key)).
> Read "Not a production posture yet" in
> `docs/plans/2026-08-08-litebox-on-kvm-design.md` before assuming anything
> about its security properties.

Unlike `litebox_runner_lvbs`, which runs in Hyper-V VTL1 as a higher-privilege
peer to a normal Linux kernel, this runner is the *whole* kernel. It boots on
bare (virtual) hardware, brings the machine up itself, and executes OP-TEE
Trusted Applications in ring 3.

Unlike `litebox_runner_optee_on_linux_userland`, it needs no syscall rewriting:
LiteBox is the kernel here, so a TA's own `syscall` instructions trap straight
to `syscall_entry`. TA binaries are used **raw**, never passed through
`litebox_syscall_rewriter`.

## Running it

```sh
./scripts/run.sh          # build and boot; runs an embedded hello-ta
./scripts/run.sh -k       # hardware acceleration (needs /dev/kvm, or sudo)
./scripts/run.sh -h       # all options
```

A successful run ends with the TA's own output and script exit status 0:

```
[INFO] sys_log msg=I/TA: Hello World!
[INFO] sys_log msg=I/TA: Goodbye!
[+] Guest completed successfully (exit 33)
```

Exit 33 rather than 0 because QEMU's `isa-debug-exit` reports `(value << 1) | 1`;
the script decodes it. 65 means the guest panicked, 124 that it hung.

### Driving it from a client

`-c` replaces the embedded sequence with a real client session over a virtio
message channel:

```sh
T=../litebox_runner_optee_on_linux_userland/tests
./scripts/run.sh -c $T/hello-ta-cmds.json                          # defaults to hello-ta
./scripts/run.sh -a $T/aes-ta.elf    -c $T/aes-ta-cmds.json
./scripts/run.sh -a $T/random-ta.elf -c $T/random-ta-cmds.json
./scripts/run.sh -a $T/kmpp-ta.elf   -c $T/kmpp-ta-cmds.json
```

`-a` and `-c` must agree — each command file is written for one TA. `-l`
overrides `ldelf`. The JSON is the same format
`litebox_runner_optee_on_linux_userland` uses, so its command files work here
unchanged.

Both binaries are **shipped to the guest over the virtqueue** in 256 KiB
chunks, so nothing is embedded on this path:

```
[client] listening on /tmp/litebox-optee-1234.sock
[client] QEMU connected
[client] -> LoadBinary ldelf: ldelf.elf (310936 bytes, 2 chunk(s))
[client] -> LoadBinary the TA: hello-ta.elf (417128 bytes, 2 chunk(s))
[client] -> OpenSession        <- status=0 ta_return=0x00000000
[client] -> InvokeCommand cmd_id=0 with 1 argument(s)
[client] -> CloseSession / Shutdown
[client] sequence completed
```

With `-c` the script's status is 0 only if *both* the client and the guest
succeeded, and it reports the client's failure in preference — the client is
the side that can say what went wrong with the exchange.

### Other flags worth knowing

- `-m 32M` starves the heap so the guest panics through its real panic handler.
- `-i <file>` attaches an initrd. QEMU reports module images as *usable* RAM,
  so this exercises the memory-map code that must withhold them from the heap.
- `-d` adds `-d int,cpu_reset`. Reach for it when the guest produces no output
  at all: a triple fault is otherwise silent.

## The virtio message channel

`src/virtio/` implements just enough of virtio 1.0 over PCI to carry
command/response frames: legacy port-I/O PCI enumeration, capability parsing, a
BAR mapped uncacheable, and split virtqueues. It **polls** the used ring, which
removes MSI-X and the whole interrupt path. `VIRTIO_CONSOLE_F_MULTIPORT` is
declined, so it is queues 0 and 1 with no control protocol.

The wire format (`src/proto.rs`) is length-prefixed with a version and opcode,
so an OP-TEE-message path can be added later as new opcodes rather than a
breaking change. Parameters mirror `UteeParamOwned`, which **owns its bytes** —
that is why this needs no shared memory, and why it is a different layer from
`OpteeMsgArgs`, whose parameters are *references* and so cannot move data on
their own.

The device is optional: with no virtio device present the runner logs a warning
and runs its embedded sequence instead.

**The same guest driver works VM-to-VM**, which is the point of choosing this
device. Only the QEMU command line differs — one side serves a socket chardev
and the other connects — so a two-VM arrangement needs no guest change.
virtio-vsock could not do this, being host-to-guest by design.

## Boot

The runner boots via the **PVH** boot protocol: QEMU's `-kernel` reads an
`XEN_ELFNOTE_PHYS32_ENTRY` note from the ELF and enters at that address in
32-bit protected mode with paging off. From there it builds early page tables,
reaches long mode, applies its own `.rela.dyn` relocations, and hands off to
`kernel_main`.

BIOS and UEFI are planned, so the boot path is split to make adding one
additive:

| | |
|---|---|
| `src/boot/mod.rs` | the firmware-neutral handoff contract, and `BootInfo` |
| `src/boot/pvh.rs` | the PVH backend: note, entry stub, trampoline, `hvm_start_info` |
| `src/boot/reloc.rs` | `.rela.dyn`, needed by any firmware loading a PIE image |
| `src/memmap.rs` | firmware-neutral: turns `BootInfo` into a heap |
| `src/pci.rs` | PCI configuration access over ports `0xCF8`/`0xCFC` |
| `src/virtio/` | capability parsing, BAR mapping, split virtqueues |
| `src/proto.rs` | the wire codec, host-tested in `dev_tests/tests/kvm_proto.rs` |
| `src/ta.rs` | the request loop, and the embedded no-device sequence |
| `src/main.rs` | everything after handoff, plus the bring-up self-checks |

**Read `src/boot/mod.rs` first if you are adding a backend.** It documents what
a backend must guarantee, what must *not* be assumed of it, and — the part most
likely to bite — which conveniences PVH happens to provide that are not part of
the contract.

## Platform root key

`KvmGuest` installs a **fixed development key**, so TAs that derive keys (such
as `kmpp-ta`) exercise the real path rather than an error path. It is
`SHA-256` of a public string in `host/kvm/mod.rs`, identical on every LiteBox-on-KVM
guest, and the guest says so three times at boot. Anything sealed with a key
derived from it is sealed against nobody.

A real deployment needs a TPM-sealed key. QEMU can attach one
(`-tpmdev emulator` with swtpm), but the guest side is a phase of work: a TPM2
driver, command marshalling, sealing — and somewhere non-volatile to keep the
sealed blob, which this guest also lacks.

## Tests

`dev_tests/tests/kvm_qemu_boot.rs` (feature `kvm_qemu`) boots real QEMU under
TCG and covers the no-device path, the channel, a panicking guest, a protocol
error, and `hello`, `aes`, `random` and `kmpp` end to end.
`dev_tests/tests/kvm_proto.rs` tests the codec on the host, including truncated
and oversized frames.

`hello3seg-ta` is deliberately **not** covered: it exists to exercise syscall
trampolines, which only the userland runners use, and it fails here for an
unrelated reason documented in
`docs/plans/2026-08-08-multi-segment-ta-loading.md`.

Note `-k` is only ever exercised by hand — CI has no `/dev/kvm`.

## Platform crate

This runner uses `litebox_platform_lvbs` with its `host_kvm` feature, not a
separate platform crate. That crate's Hyper-V specifics are gated behind
`host_lvbs`; the rest is a generic x86_64 kernel shared by both hosts.
