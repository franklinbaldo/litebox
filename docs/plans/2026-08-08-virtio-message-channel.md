# virtio message channel for the KVM runner

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the KVM runner's hardcoded TA sequence with a virtqueue-based command/response channel, so an external client drives session open / command invoke / session close.

**Architecture:** A polling virtio-serial-pci driver in the guest, discovered over legacy PCI config I/O, with a length-prefixed binary protocol carrying `UteeParamOwned`-shaped commands. The host client is a socket-backed chardev.

**Tech Stack:** Rust `nightly-2025-12-31`, `no_std`, custom target `x86_64_kvm.json`, QEMU 8.2.2.

---

## Why this shape

Recorded so the choices are not relitigated. Each was checked against the code or QEMU.

**Why `UteeParamOwned` and not `OpteeMsgArgs`.** `litebox_runner_optee_on_linux_userland` — the model we are copying — does *not* use the OP-TEE message layer. `tests.rs:278` builds `UteeParamOwned` and calls `entrypoints.load_ta_context(&params, session_id, func_id, ..)` directly. Crucially, `UteeParamOwned::MemrefInput { data: Box<[u8]> }` **owns its bytes**, whereas `OpteeMsgArgs` params are a 24-byte union that is either three inline `u64`s or a *reference* (`Tmem.buf_ptr` is a physical address, `Rmem` is an offset into registered shared memory).

An OP-TEE message therefore carries references, not data — it is insufficient on its own to move a buffer. Speaking that layer requires either real shared memory or an envelope that re-materialises the referenced buffers. `UteeParamOwned` sidesteps this entirely, which is why the userland runner needs no shared memory at all.

**Why virtio-serial-pci.** It is the simplest QEMU virtio device offering a bidirectional message channel on q35, and — the deciding factor — **the same guest driver works unchanged between host↔guest and VM↔VM.** Only the QEMU command line differs:

```sh
# secure VM                                    # normal-world VM
-chardev socket,id=c,path=/tmp/s,server=on     -chardev socket,id=c,path=/tmp/s
-device virtio-serial-pci,id=vs0               -device virtio-serial-pci,id=vs0
-device virtconsole,chardev=c,bus=vs0.0        -device virtconsole,chardev=c,bus=vs0.0
```

virtio-vsock would *not* work for VM↔VM: vsock is host↔guest by design, CID-addressed, with no standard guest-to-guest form.

**Why polling.** Removes MSI-X, IOAPIC and the whole interrupt path. The guest has nothing else to do while waiting.

**Why legacy PCI config I/O.** Config space is reachable via ports `0xCF8`/`0xCFC`, so no ECAM mapping is needed. Only the device's BAR MMIO must be mapped, and that is above `MAPPED_LIMIT` — see Task 3.

**Why not `virtio-drivers` and `pci_types`, i.e. why this driver is ours.** The original plan never recorded this, which is a gap: reusing a maintained crate is the better default and should have been the first question. Both were evaluated properly — built for `x86_64_kvm.json`, then driven against the malformed-input tests in `src/virtio/queue.rs` and `src/pci/` — and both were rejected **on correctness**, not on threat model. The peer today is the host, which already owns guest memory; these are ordinary spec and robustness defects that hold against a merely buggy peer.

`pci_types` 0.10.1: `PciHeader::update_command` (`lib.rs:194`) read-modify-writes the whole dword at `0x04`, writing `STATUS` back as read and so clearing RW1C bits — the bug `cdd66696` removed. `CapabilityIterator::next` (`capability/mod.rs:129`) has no bound but `offset == 0`, so a cyclic list hangs. `bar()` sizes without clearing `MEMORY_ENABLE`, aliasing a live BAR, and `lib.rs:380` panics on a device-reported reserved memory type. Net reusable after excluding those: ~40 lines.

`virtio-drivers` 0.13.0: `pop_used` (`queue.rs:536`) returns `WrongToken` *before* advancing `last_used_idx`, so one bogus used-ring id wedges the ring permanently — measured as `recv()` returning `Ok(None)` forever, silently. `recycle_descriptors` (`queue.rs:486`) does an unguarded `num_used -= 1`, self-linking the free list on a replayed id: the same bug `e7b44d29` fixed, still live upstream. `console.rs:208` sets `pending_len` from the device's `len` with no clamp against the 4 KiB buffer, and `console.rs:190` is a bare `assert_ne!` on a device value. Its capability walk (`transport/pci/bus.rs:543`) rejects `next < 64` and misaligned offsets — better than `pci_types` — but has no visited set, so a cycle still hangs. `begin_init` never re-reads `FEATURES_OK`, which virtio 1.0 §3.1.1 step 6 requires and `virtio/mod.rs:990` does.

Two things are *not* the reason, and should not be recycled as arguments: both crates cross-compile to our target cleanly, and `Hal`/`ConfigurationAccess` are both satisfiable here (`ConfigurationAccess` is CF8/CFC-shaped, so the README's "memory-mapped CAM only" is about the provided `MmioCam`, not the trait). Adoption also does not pay for itself: `virtio-drivers` would delete ~375 lines of `Queue` while requiring a ~250-line `Transport` impl, or else pull in its 946-line `bus.rs` alongside the `pci/mod.rs` we keep.

Neither crate has a deadline-bounded receive — no `abandon`/`forget_posted_buffer` equivalent — which `Console::receive_deadline` needs. Revisit if that changes upstream, or if VM↔VM stops being artificial and the hardening has to be re-argued anyway.

## What this does not solve, and must not pretend to

- Two normal VMs are **symmetrically isolated**. Unlike LVBS, where VTL1 is more privileged and can map arbitrary VTL0 GPAs (which is what `NormalWorldConstPtr = PhysConstPtr<T, ALIGN, Vmap>` relies on), neither VM can reach the other's memory. This channel moves *data by value*; it does not create a shared address space.
- Consequently `OpteeMsgArgs` with `Tmem` can never work across two VMs regardless of transport. `Rmem` (offset-based) can, but only with a real shared region.
- Making a *stock* OP-TEE client allocate inside such a region needs LiteBox to advertise `HAVE_RESERVED_SHM` and withhold `DYNAMIC_SHM` (today `msg_handler.rs:279` advertises `DYNAMIC_SHM | MEMREF_NULL | RPC_ARG`), plus an implementation of `OPTEE_SMC_GET_SHM_CONFIG`, which does not exist in this tree.

None of that is in scope here. It is recorded so the next person does not rediscover it.

## Verification gates

After every task:

```bash
/tmp/lvbs-check.sh      # LVBS invariant; expect Gate A' de61da67… MATCH, 12599 MATCH
./litebox_runner_optee_on_kvm/scripts/run.sh          # still boots and runs the TA
cargo +nightly-2025-12-31 nextest run -p dev_tests --features kvm_qemu --test kvm_qemu_boot
```

Tasks 1-5 must not change observable behaviour: the runner still runs its embedded TA sequence. Only Task 6 switches it over.

**Standing hazards:** gate `cfg` at the item level, never inside a function body. Disassemble any assembly you write — LLVM's Intel-syntax parser silently mis-assembles symbol arithmetic in immediates. QEMU's default `qemu64` lacks RDRAND and FSGSBASE, so use `-cpu max`.

---

### Task 1: 32-bit port I/O and PCI config access

**Files:** `litebox_platform_lvbs/src/arch/x86/ioport.rs` (host-neutral additions), new `litebox_runner_optee_on_kvm/src/pci.rs`

**Step 1** — `ioport.rs` has private `inb`/`outb` and no 32-bit forms. Add `inl`/`outl`. These are architectural, so they are **not** host-gated — but that means they land in the LVBS build too. Adding unused `pub` functions should not move the LVBS gate; **verify, and if it moves, gate them `host_kvm` and say so.**

**Step 2** — implement PCI type-1 configuration access in `pci.rs`: write `0x8000_0000 | bus<<16 | dev<<11 | func<<8 | (offset & 0xFC)` to `0xCF8`, read/write `0xCFC`.

**Step 3** — enumerate bus 0 (QEMU puts virtio devices there) looking for vendor `0x1AF4`. Report device ID, and read the capability list pointer at offset `0x34`.

**Step 4** — log every virtio device found with its BDF, device ID and BARs. Verify against `-device virtio-serial-pci`. Do not proceed until the device is visible.

Commit: `Add PCI configuration access over legacy port I/O`

---

### Task 2: virtio PCI capability parsing

**Files:** `litebox_runner_optee_on_kvm/src/pci.rs`, new `litebox_runner_optee_on_kvm/src/virtio/mod.rs`

Walk the PCI capability list for vendor-specific capabilities (ID `0x09`) with the virtio structure layout: `cfg_type`, `bar`, `offset`, `length`. Locate:

| `cfg_type` | Structure |
|---|---|
| 1 | common configuration |
| 2 | notification |
| 3 | ISR status |
| 4 | device-specific configuration |

Record which BAR each lives in and at what offset. Note the notify capability has an extra `notify_off_multiplier` field.

Log all of it. This is pure discovery — nothing is mapped yet.

Commit: `Parse virtio PCI capability structures`

---

### Task 3: map BAR MMIO

**Files:** `litebox_runner_optee_on_kvm/src/virtio/mod.rs`, possibly `litebox_runner_optee_on_kvm/src/boot/mod.rs`

Measured facts from Task 2, which correct this plan as first written:

- The device QEMU gives us is **transitional**: device ID `0x1003`, with a legacy I/O interface at BAR0 (port `0xC000`) *and* the full modern capability set. Adding `disable-legacy=on` to the QEMU line makes it `0x1043` with byte-identical capability offsets; doing so is worthwhile to make the modern-only contract explicit rather than incidental.
- **All four structures live in BAR4**, one 4 KiB page each, contiguous over `0x0000..0x4000`. So only **16 KiB** needs mapping, not "the BARs".
- **BAR4 is 64-bit and prefetchable**, base `0xFE00_0000`. The earlier claim that BARs sit above the ECAM window at `0xB000_0000` was wrong about ordering; both are above `MAPPED_LIMIT` (1 GiB), so the conclusion stands but the address does not.
- `notify_off_multiplier` is **4**, not 0, so each queue has its own notify dword at `bar4 + 0x3000 + queue_notify_off * 4`.

**Step 1** — read the BAR, determine its size by the standard write-all-ones-and-read-back dance, and restore it. **BAR4 is 64-bit**: write ones to *both* halves and restore both, or you will corrupt the upper dword.

**Step 2** — map those physical pages into the kernel window. **MMIO must be mapped uncacheable** (`PCD`/`PWT`, or a PAT entry) — mapping device registers write-back will produce baffling behaviour.

**Step 3** — prove it: read the virtio common configuration's `device_feature` after selecting feature word 0, and confirm bit 32 (`VIRTIO_F_VERSION_1`) is offered once you select word 1. A plausible non-zero read is the evidence that the mapping and the capability offsets are both right.

Commit: `Map virtio BAR MMIO into the kernel window`

---

### Task 4: device initialisation and virtqueue setup

**Files:** `litebox_runner_optee_on_kvm/src/virtio/mod.rs`, new `litebox_runner_optee_on_kvm/src/virtio/queue.rs`

**Step 1** — the virtio 1.0 status handshake: `ACKNOWLEDGE`, `DRIVER`, negotiate features, `FEATURES_OK`, read back to confirm, set up queues, `DRIVER_OK`. Fail loudly at each step rather than proceeding.

Negotiate `VIRTIO_F_VERSION_1` and as little else as possible.

**Step 2** — split virtqueue: descriptor table (16 bytes/entry), available ring, used ring. Each must be physically contiguous and appropriately aligned; allocate whole pages. Write the physical addresses into the common configuration's `queue_desc` / `queue_driver` / `queue_device`, set `queue_size`, then `queue_enable`.

Remember the platform maps `VA = PA + KERNEL_OFFSET`, so `va_to_pa` gives what the device needs.

**Step 3** — **the fiddly part: which queues.** `virtio-serial-pci` is the multiport controller. With `VIRTIO_CONSOLE_F_MULTIPORT` negotiated the layout is queue 0 = port 0 receive, 1 = port 0 transmit, 2 = control receive, 3 = control transmit, 4/5 = port 1, and so on; a `virtconsole` device may attach at port 0 or port 1 depending on configuration.

**Determine this empirically rather than from the spec alone.** Try declining `F_MULTIPORT` first — if QEMU still delivers on queues 0/1, that is much less machinery. If the control queue turns out to be required to mark the port open, implement just enough of it. Report which you found and why.

**Step 4** — a loopback proof: put a buffer on the transmit queue, notify, and confirm the device consumes it by polling the used ring. With `-chardev socket` and a listener attached you should see the bytes arrive host-side.

Commit: `Bring up the virtio device and its virtqueues`

---

### Task 5: the wire protocol

**Files:** new `litebox_runner_optee_on_kvm/src/proto.rs`

Length-prefixed framing, because virtio-console is a byte stream and does not preserve message boundaries.

```
[u32 len][u16 version][u16 opcode][payload…]
```

`version` and `opcode` exist so the `OpteeMsgArgs` path can later be added as new opcodes rather than a breaking change. Reject unknown versions explicitly.

Opcodes for this cut mirror `TaEntryFunc`: `OpenSession`, `InvokeCommand`, `CloseSession`, plus a `Response`.

Parameters mirror `UteeParamOwned`'s six variants — `ValueInput/Output/Inout`, `MemrefInput/Output/Inout` — encoded as a tag plus either two `u64`s or a length-prefixed byte string. Memref *outputs* carry a size on request and bytes on response.

Encode and decode with explicit bounds checks. **This parses untrusted input from outside the guest: every length must be validated against the buffer before use.** Add `#[cfg(test)]` round-trip tests, including truncated and oversized frames — these are pure functions and testable on the host, unlike most of this crate.

Commit: `Add the virtio message-channel wire protocol`

---

### Task 6: drive the shim from the channel

**Files:** `litebox_runner_optee_on_kvm/src/ta.rs`, `litebox_runner_optee_on_kvm/src/main.rs`

Replace the hardcoded open/invoke/close sequence with a request loop:

```
loop {
    let req = channel.recv()?;
    let resp = match req.opcode {
        OpenSession   => …try_acquire_open_session_token, load_ldelf, run_thread_ref…
        InvokeCommand => …load_ta_context(&params, session_id, func_id), reenter_thread_ref…
        CloseSession  => …
        Shutdown      => break,
    };
    channel.send(resp)?;
}
exit(SUCCESS)
```

Keep `ldelf` and the TA embedded via `include_bytes!` for now — shipping binaries over the wire is a later cut.

The existing sequence is the reference for what each opcode must do; `litebox_runner_optee_on_linux_userland/src/lib.rs:105-149` and `tests.rs` are the model for parameter handling.

**A `Shutdown` opcode matters**: without it there is no way for the guest to exit cleanly, and the integration test would depend on the timeout.

Commit: `Drive the OP-TEE shim from the virtio message channel`

---

### Task 7: host client

**Files:** new `litebox_runner_optee_on_kvm/scripts/client.py`

A small Python client that connects to the unix socket and issues a command sequence, reusing the JSON shape of `litebox_runner_optee_on_linux_userland/tests/hello-ta-cmds.json` so the existing files work unchanged.

It must print the TA's responses and exit non-zero on a protocol or TA error.

Update `scripts/run.sh` with a flag to add the virtio device and chardev, and to start the client.

Commit: `Add a host-side client for the virtio message channel`

---

### Task 8: integration test and CI

**Files:** `dev_tests/tests/kvm_qemu_boot.rs` or a sibling, `.github/workflows/ci.yml`

Extend the QEMU test to run a client session end to end and assert on the TA's actual output — not merely the exit status. Keep the existing embedded-TA test if it still has value, or replace it if Task 6 removed the path it exercised.

Assert the failure path too: a malformed frame must produce a clean error, not a hang.

Commit: `Test the virtio message channel end to end`

---

## Definition of done

- An external client opens a session, invokes commands with value parameters, closes, and shuts the guest down.
- The guest never parses an unvalidated length.
- LVBS gate unmoved.
- CI runs the client end to end under TCG.

## Deferred

Memref parameters over the wire, TA binaries over the wire, `OpteeMsgArgs` opcodes, shared memory of any kind, and the two-VM topology — which needs no guest change beyond what this plan builds.
