# MIG Message Emulation Design

**Date:** 2026-04-10
**Branch:** sanghle/arm64/mac/shim8
**Goal:** Make whoami, id, and stat exit cleanly by emulating MIG (Mach Interface Generator) messages.

## Background

Three system binaries (whoami, id, stat) crash with exit 133 (SIGTRAP) because they
depend on Mach IPC that litebox does not handle. Instrumentation revealed the exact
crash sequence — all three binaries hit the same two calls before crashing:

1. `mach_msg2` trap 47 with `msgh_id=412` (`host_get_special_port` from `host_priv` subsystem)
   - Sends to HOST_SELF (0x0503), expects reply on port 0x0403
   - Request body: NDR record, node=-1, which=1 (HOST_PORT)
   - Currently returns `MACH_SEND_INVALID_DEST` (0x10000003)

2. `host_create_mach_voucher` trap 70
   - host=0x0503, recipes=<shared cache addr>, sz=16, voucher_out=<stack addr>
   - Currently returns `KERN_INVALID_ARGUMENT` (4)
   - Crash occurs after this returns failure

The BSD `mach_msg2` call during dyld startup returns `MACH_SEND_INVALID_DEST` and dyld
handles it gracefully — no change needed there.

## Architecture

### New Module: `litebox_shim_macos/src/mig/`

```
mig/
  mod.rs         -- wire format structs, MigDispatcher, dispatch_mig()
  host_priv.rs   -- host_priv subsystem (base 400), host_get_special_port (412)
```

### Wire Format Structs (mod.rs)

All `#[repr(C)]`, read/written via ConstPtr/MutPtr on guest memory.

`MachMsgHeader` (24 bytes):
- msgh_bits: u32
- msgh_size: u32
- msgh_remote_port: u32
- msgh_local_port: u32
- msgh_voucher_port: u32
- msgh_id: i32

`MachMsgBody` (4 bytes):
- msgh_descriptor_count: u32

`MachMsgPortDescriptor` (8 bytes):
- name: u32
- disposition_type: u32  (packed: disposition in bits 16-23, type=0 in bits 24-31)

`NdrRecord` (8 bytes):
- Constant: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00] (little-endian)

### MIG Dispatcher (mod.rs)

```rust
pub fn dispatch_mig(
    &self,
    msg_addr: usize,     // guest address of request message
    options: usize,      // mach_msg options (SEND|RCV flags)
    ctx: &mut PtRegs,
) -> Result<usize, Errno>
```

Steps:
1. Read `MachMsgHeader` from `msg_addr`
2. Extract `msgh_id`
3. Match on msgh_id range:
   - 400..500 -> host_priv::dispatch()
   - unknown  -> return MACH_SEND_INVALID_DEST
4. If handler succeeded and options includes MACH_RCV_MSG, write reply to `msg_addr`
5. Return MACH_MSG_SUCCESS (0)

### host_priv Subsystem (host_priv.rs)

Subsystem base: 400. MIG reply ID = request ID + 100.

**Routine 412: host_get_special_port**

Request body (after header, 16 bytes):
- NDR_record (8 bytes)
- node: i32 (-1 = HOST_LOCAL_NODE)
- which: i32 (1 = HOST_PORT, etc.)

Reply (36 bytes total, complex):
- Header: msgh_bits=0x1200 (MOVE_SEND_ONCE | COMPLEX), size=36,
  remote=<request.msgh_local_port>, local=0, voucher=0, id=512
- Body: descriptor_count=1
- Port descriptor: name=<port for requested special port>, disposition+type packed

Port mapping for `which`:
- 1 (HOST_PORT) -> 0x0503
- 2 (HOST_PRIV_PORT) -> 0x0503 (same, we are the only task)
- Other -> allocate from next_mach_port or return KERN_INVALID_ARGUMENT

### host_create_mach_voucher (trap 70, in stubs.rs)

Not MIG — this is a fast-path Mach trap. Fix:
- Return KERN_SUCCESS (0)
- Write a fake voucher port name (allocated from next_mach_port) to *voucher_out (x3)

### mach_msg / mach_msg2 Trap Changes (stubs.rs)

**mach_msg_trap (trap 31):**
- Read msg header from ctx.regs[0]
- If options include SEND: call dispatch_mig()
- If only RCV: return MACH_RCV_INVALID_NAME (not implemented yet)

**mach_msg2 (trap 47):**
- Same as trap 31 but args in ctx.regs[0..6]

**BSD mach_msg2 (x16=0x80000000):**
- Args from MachMsg2Trap variant: data, options, msgh_bits
- Call dispatch_mig(data, options)
- Note: msgh_bits arg may override the header bits field (mach_msg2 compact encoding)

**mach_msg_overwrite (trap 32):**
- Same as trap 31, separate receive buffer pointer (not needed for send+receive to same buffer)

## Iterative Approach

After implementing the above, re-run whoami/id/stat. They will likely get past the
current crash and make additional MIG calls (e.g., bootstrap_look_up for
opendirectoryd, then MIG to the directory service for getpwuid). Each iteration:

1. Run binary, capture mach_msg2 logs (msgh_id + body)
2. Decode MIG subsystem + routine from XNU .defs files
3. Implement handler in appropriate subsystem file
4. Repeat until binary exits cleanly

Expected additional subsystems needed:
- bootstrap (subsystem 1000): bootstrap_look_up to resolve service names to ports
- mach_host (subsystem 200): host_info, host_statistics
- task (subsystem 3400): task_info, task_get_special_port
- Directory services: getpwuid/getgrgid responses (subsystem TBD after instrumentation)

## Success Criteria

- whoami exits 0
- id exits 0
- stat (with a valid path like /) exits 0
- All existing tests continue to pass (41 passed, 0 failed, 3 ignored)
- Clippy clean, docs clean

## Constraints

- `#![no_std]` with `extern crate alloc`
- No trait objects — use match-based dispatch
- Guest memory access via ConstPtr/MutPtr
- Synthetic/fake values are acceptable (litebox is a libOS)
- log_unsupported!() for diagnostics, no eprintln!
