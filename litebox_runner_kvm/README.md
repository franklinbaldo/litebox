# A LiteBox Runner for running LiteBox as a guest kernel under KVM/QEMU

> [!WARNING]
> This crate is work in progress. See "Not a production posture yet" in
> `docs/plans/2026-08-08-litebox-on-kvm-design.md` before assuming anything
> about its security properties.

Unlike `litebox_runner_lvbs`, which runs in Hyper-V VTL1 as a higher-privilege
peer to a normal Linux kernel, this runner is the *whole* kernel. It boots on
bare (virtual) hardware, brings the machine up itself, and executes an OP-TEE
Trusted Application in ring 3.

## Running it

```sh
./scripts/run.sh          # build and boot under TCG emulation
./scripts/run.sh -k       # use hardware acceleration (needs /dev/kvm)
./scripts/run.sh -h       # all options
```

A successful run ends with the TA's own output and exit status 0:

```
[INFO] sys_log msg=I/TA: Hello World!
[INFO] sys_log msg=I/TA: Goodbye!
[+] Guest completed successfully (exit 33)
```

Two options are worth knowing about, because they exercise paths that are
otherwise only covered by the integration test:

- `-m 32M` starves the heap, so the guest panics through its real panic
  handler. Use it to check the failure path still fails.
- `-i <file>` attaches an initrd. QEMU reports module images as usable RAM, so
  this exercises the memory-map code that must withhold them from the heap.

The integration test in `dev_tests/tests/kvm_qemu_boot.rs` runs both the
success and failure paths under TCG, and is what CI uses.

## Boot

The runner boots via the **PVH** boot protocol: QEMU's `-kernel` reads an
`XEN_ELFNOTE_PHYS32_ENTRY` note from the ELF and enters at that address in
32-bit protected mode with paging off. From there the runner builds early page
tables, reaches long mode, applies its own `.rela.dyn` relocations, and hands
off to `kernel_main`.

BIOS and UEFI are planned. The boot path is therefore split so that adding one
is additive:

| | |
|---|---|
| `src/boot/mod.rs` | the firmware-neutral handoff contract, and `BootInfo` |
| `src/boot/pvh.rs` | the PVH backend: note, entry stub, trampoline, `hvm_start_info` |
| `src/boot/reloc.rs` | `.rela.dyn`, needed by any firmware loading a PIE image |
| `src/memmap.rs` | firmware-neutral: turns `BootInfo` into a heap |
| `src/main.rs` | everything after handoff |
| `src/ta.rs` | loading and running the Trusted Application |

**Read `src/boot/mod.rs` first if you are adding a backend.** It documents what
a backend must guarantee, what it must *not* be assumed to have done, and — the
part most likely to bite — which conveniences PVH happens to provide that are
not part of the contract.

## Platform

This runner uses `litebox_platform_lvbs` with its `host_kvm` feature, not a
separate platform crate. That crate's Hyper-V specifics are gated behind
`host_lvbs`; the rest is a generic x86_64 kernel shared by both hosts.
