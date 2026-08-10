// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for a plain KVM/QEMU guest.
//!
//! Unlike LVBS, LiteBox here *is* the kernel: there is no VTL0 peer to delegate
//! to. The security boundary is ring 0 vs ring 3, enforced by page tables,
//! SMEP/SMAP and the syscall gate — a conventional OS threat model rather than
//! a VBS one. `litebox_runner_optee_on_kvm` establishes that boundary; see the
//! `set_physical_memory_protections` comment in `crate::lib` for the argument
//! and where each half of it is set up.
//!
//! # Inventory
//!
//! This module is no longer a set of stubs. As of Phase 2 the guest boots via
//! PVH, reaches long mode, and runs an OP-TEE TA in ring 3, so most of what is
//! here is load-bearing. What is missing is missing for three distinct
//! reasons, and the distinction matters when reading a panic.
//!
//! ## Implemented
//!
//! * **The heap.** A `SafeZoneAllocator` registered as the
//!   `#[global_allocator]` and wired to `litebox::mm::allocator::MemoryProvider`
//!   and [`crate::mm::MemoryProvider`]. The runner walks the PVH memory map and
//!   hands every usable region to [`heap_add_region`] at boot.
//! * **The logger.** [`HostInterface::log`] writes to the 16550 UART.
//! * **The clock.** `Instant::now()` reads the TSC and rescales to nanoseconds
//!   (in `crate::lib`, not here). LVBS's Hyper-V reference counter does not
//!   exist on this platform.
//! * **The CRNG.** A ChaCha20 DRBG seeded and periodically reseeded from
//!   RDRAND, exposed through `litebox::platform::CrngProvider`. See `KvmCrng`.
//! * **The exit paths.** [`HostInterface::exit`] and
//!   [`HostInterface::terminate`] end the guest through QEMU's `isa-debug-exit`
//!   device; [`debug_exit`] documents the exit-status transform.
//! * **Reboot-persistent key derivation, on an emulated root key.**
//!   `litebox::platform::DerivedKeyProvider` derives from a PRK installed by
//!   [`install_development_platform_root_key`], which the runner calls at boot.
//!   Read that function before believing this line: the key is a **development
//!   key with no security value** — SHA-256 of a fixed ASCII string, public,
//!   and identical on every guest. It emulates what a vTPM would provide so
//!   that TAs exercise the real derivation path instead of the refusal path,
//!   and it warns loudly on every boot that it is doing so. Whether it is
//!   "implemented" depends on what you were asking: the *mechanism* is real
//!   and mirrors `host::lvbs` (no raw PRK getter, shim-supplied KDF required);
//!   the *root of trust* is absent, and a real deployment needs a TPM-sealed
//!   key. See "Not built yet" below for what that would cost.
//!
//! ## Not built yet — `unimplemented!()`
//!
//! These are genuinely absent and someone should write them. Each will be
//! needed by a specific piece of post-milestone-1 work:
//!
//! * [`HostInterface::wake_many`] and [`HostInterface::block_or_maybe_timeout`]
//!   — the futex backend. Nothing multi-threaded runs here yet: there is no AP
//!   bring-up and no preemption timer, so no thread has ever needed to block.
//! * [`HostInterface::send_ip_packet`] and
//!   [`HostInterface::receive_ip_packet`] — virtio-net. There is no network
//!   device on the QEMU command line to drive.
//! * **A real root of trust for the PRK.** QEMU supports `-tpmdev emulator`
//!   backed by swtpm, which puts a TPM 2.0 device in front of the guest, and a
//!   key sealed to it would give the reboot-persistence property LVBS gets from
//!   its VBS-provisioned PRK. Nothing about that is free on the guest side: it
//!   needs a TPM2 driver for whichever interface QEMU exposes (TIS or CRB, both
//!   MMIO, plus the ACPI or device-tree plumbing to find it), command and
//!   response marshalling for the TPM2 command set, and then the sealing policy
//!   itself — `TPM2_CreatePrimary` under the storage hierarchy, `TPM2_Create`
//!   and `TPM2_Load` for the sealed blob, `TPM2_Unseal` at boot, and somewhere
//!   non-volatile to keep the blob between boots, which this guest also does
//!   not have. That is a phase of work, not a patch, which is why the
//!   development key above exists in the meantime.
//!
//! ## Cannot exist here
//!
//! Not gaps. These would be wrong to implement, and are deliberately *not*
//! `unimplemented!()` so that they do not read as a to-do list:
//!
//! * [`HostInterface::switch`] is `unreachable!()`. It transfers control to
//!   VTL0, and a plain KVM guest has no VTL0 peer to transfer to. There is no
//!   future in which this gains a body.
//!
//! ## Compiled out silently — no panic to read
//!
//! One gap is in none of the categories above, which is exactly why it is
//! called out separately: it neither works nor fails.
//!
//! * **The preemption timer.** `crate::run_thread` arms it under
//!   `#[cfg(feature = "host_lvbs")]` only (`lib.rs:1505`), because the LVBS
//!   implementation is built on Hyper-V synthetic timers and there is no such
//!   thing here. On `host_kvm` the call simply is not emitted. Nothing panics
//!   and nothing logs; a TA that loops in ring 3 is never interrupted and
//!   wedges the machine permanently, with no diagnostic connecting the hang to
//!   this line. Replacing it needs an APIC-deadline source. Until then, ring-3
//!   code here is trusted not to loop -- which is tolerable for a test vehicle
//!   running TAs we build, and is not a production posture. See the
//!   "Not a production posture yet" section of
//!   `docs/plans/2026-08-08-litebox-on-kvm-design.md`.
//!
//! ## Absent entirely
//!
//! `litebox::platform::ThreadLocalStorageProvider` and `init_task` are
//! implemented for `LvbsLinuxKernel` but have no `KvmGuest` counterpart — not
//! even a stub. Nothing in the crate demands those bounds on this path yet, so
//! the omission compiles. Neither is LVBS-specific (TLS is just `pcv.tls`), so
//! both are straightforward ports whenever a caller first needs them.
//!

/// TSC-based monotonic clock. KVM guests have no Hyper-V reference counter,
/// so the TSC is the only cheap monotonic source available.
pub mod clock;

use crate::{Errno, HostInterface, arch::ioport::serial_print_string};
use digest::Digest;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

pub type KvmGuest = crate::LinuxKernel<HostKvmInterface>;

pub struct HostKvmInterface;

// ---------------------------------------------------------------------------
// The heap.
//
// Structurally this mirrors the `alloc` module in `host/lvbs/mod.rs`: a
// `SafeZoneAllocator` (buddy allocator for pages, slab allocator for small
// objects) registered as the `#[global_allocator]` and wired to both
// `litebox::mm::allocator::MemoryProvider` and `crate::mm::MemoryProvider`.
//
// The one substantive difference is where the memory comes from. LVBS runs in
// VTL1 with VTL0 as a peer that can be asked for more pages, so its
// `MemoryProvider::alloc` rescue hook has somewhere to go (in practice LVBS
// has not implemented it either -- it `panic!`s). Here LiteBox *is* the
// kernel: the guest's RAM is described exactly once, by the PVH memory map at
// boot, and there is no higher authority to ask. So the runner walks that map
// and hands every usable region to `heap_add_region` up front, and the rescue
// hook honestly reports exhaustion rather than pretending.
// ---------------------------------------------------------------------------

#[cfg(not(test))]
mod heap {
    /// Maximum buddy order.
    ///
    /// The buddy allocator keeps `ORDER` free lists and can therefore serve a
    /// single block of at most `1 << (ORDER - 1)` bytes. LVBS uses 25 (16 MiB),
    /// sized for the fixed slice VTL0 hands it.
    ///
    /// A KVM guest instead owns all of its RAM, and we boot with `-m 512M`. 30
    /// gives a 512 MiB maximum block, which is the entire machine: no allocation
    /// that could possibly be backed will be rejected for being too large, and
    /// the rescue hook's `unimplemented!("requested size ... is too large")` arm
    /// becomes unreachable for any request that RAM could satisfy. The cost is one
    /// `LinkedList` (a single pointer) per extra order -- 40 bytes of `.bss` over
    /// LVBS -- so there is no reason to be stingy. Raise it if the guest is ever
    /// given more than 512 MiB and someone wants a single allocation larger than
    /// that.
    ///
    /// Declared inside this module rather than beside it so it does not become
    /// dead code under `cfg(test)`, where the allocator is not compiled;
    /// `host::lvbs` does the same.
    const HEAP_ORDER: usize = 30;

    #[global_allocator]
    pub(super) static KVM_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::KvmGuest,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    impl litebox::mm::allocator::MemoryProvider for super::KvmGuest {
        fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            <super::HostKvmInterface as crate::HostInterface>::alloc(layout)
        }

        unsafe fn free(addr: usize) {
            unsafe { <super::HostKvmInterface as crate::HostInterface>::free(addr) }
        }
    }

    impl crate::mm::MemoryProvider for super::KvmGuest {
        /// A plain higher-half offset; nothing VSM-specific about it, so it
        /// matches the LVBS value.
        const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
        /// A plain KVM guest has no memory-encryption bit to set in the PTE.
        const PRIVATE_PTE_MASK: u64 = 0;

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            KVM_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe { KVM_ALLOCATOR.free_pages(ptr, order) };
        }

        unsafe fn mem_fill_pages(start: usize, size: usize) {
            unsafe { KVM_ALLOCATOR.fill_pages(start, size) };
        }
    }
}

#[cfg(test)]
impl crate::mm::MemoryProvider for KvmGuest {
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        unimplemented!("not used in tests")
    }

    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        unimplemented!("not used in tests")
    }
}

/// Gives the heap ownership of the half-open kernel-virtual range
/// `[start, start + size)`.
///
/// The boot path calls this once per usable region of the PVH memory map,
/// before anything allocates. There is no other way to grow the heap: see the
/// module comment above.
///
/// # Safety
///
/// The caller must ensure the range is mapped, writable, and not used by
/// anything else for the lifetime of the kernel -- in particular that it does
/// not overlap the loaded image, the page tables, or any stack. The heap takes
/// ownership and will hand the bytes out to arbitrary callers.
#[cfg(not(test))]
pub unsafe fn heap_add_region(start: usize, size: usize) {
    unsafe { heap::KVM_ALLOCATOR.fill_pages(start, size) };
}

// ---------------------------------------------------------------------------
// Stopping the machine.
//
// QEMU's `isa-debug-exit` device is the only way a `-kernel` guest can end the
// emulator with a value of its own choosing. The runner puts it on the command
// line as `-device isa-debug-exit,iobase=0xf4,iosize=0x04`; a single write to
// that port terminates QEMU.
//
// **QEMU does not use the written value as the process exit status.** It calls
// `exit((value << 1) | 1)`. The low bit is forced set precisely so that a guest
// can never produce status 0, which is reserved for "QEMU itself finished
// normally" -- i.e. a guest that never wrote to the port at all. So:
//
//     written 0x10 (DEBUG_EXIT_SUCCESS) -> shell sees 33 (0x21)
//     written 0x20 (DEBUG_EXIT_FAILURE) -> shell sees 65 (0x41)
//
// This is why "success" here is *not* exit code 0, and cannot be made to be.
// Callers outside the guest must compare against the transformed values; the
// two constants below are the guest-side halves, and the transform is applied
// by QEMU.
//
// The values themselves are arbitrary but deliberately not 0 and 1: those
// transform to 1 and 3, which collide with the exit statuses of a QEMU that
// failed to start and of a shell reporting a signal. 33 and 65 collide with
// nothing we produce.
// ---------------------------------------------------------------------------

/// The `isa-debug-exit` I/O port, matching `iobase=0xf4` on the QEMU command
/// line.
pub const DEBUG_EXIT_PORT: u16 = 0xf4;

/// Value written to end the guest successfully. QEMU turns this into process
/// exit status 33.
pub const DEBUG_EXIT_SUCCESS: u32 = 0x10;

/// Value written to end the guest with a failure. QEMU turns this into process
/// exit status 65.
pub const DEBUG_EXIT_FAILURE: u32 = 0x20;

/// Writes `value` to the `isa-debug-exit` port, then halts.
///
/// The halt is not dead code. If the device is absent -- someone running the
/// image under a QEMU invocation without `-device isa-debug-exit`, or under a
/// different VMM entirely -- the `out` is discarded and execution continues.
/// Falling into `hlt_loop` keeps the `-> !` signature honest and leaves the
/// machine in a defined, quiet state rather than running off the end of the
/// function.
pub fn debug_exit(value: u32) -> ! {
    // SAFETY: a 32-bit write to the `isa-debug-exit` port. The port is either
    // the debug-exit device, in which case this write does not return, or
    // unclaimed, in which case the write is discarded. Neither touches memory.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") DEBUG_EXIT_PORT,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    crate::arch::instrs::hlt_loop()
}

impl HostInterface for HostKvmInterface {
    fn log(msg: &str) {
        serial_print_string(msg);
    }

    /// The buddy allocator's rescue hook, called only once the heap is empty.
    ///
    /// There is nothing to do. On LVBS this would be a request to VTL0; here
    /// LiteBox is the kernel and every byte of RAM the PVH memory map
    /// described was handed to the heap at boot. Returning `None` reports
    /// genuine exhaustion, which is the truth, rather than `panic!`-ing on a
    /// path that a caller may be prepared to handle.
    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        None
    }

    /// Unreachable: [`Self::alloc`] never hands out a region, so nothing can
    /// be given back.
    unsafe fn free(_addr: usize) {
        unreachable!("nothing was ever obtained from a host to return")
    }

    /// Ends the guest successfully.
    ///
    /// On LVBS `exit()` returns to VTL0 and execution resumes later. There is
    /// nobody to return to here, so the only meaningful "exit" is to stop the
    /// machine -- see [`debug_exit`] for how, and for why the process exit code
    /// is not the value written.
    fn exit() -> ! {
        debug_exit(DEBUG_EXIT_SUCCESS)
    }

    /// Ends the guest with a failure indication.
    ///
    /// The reason is logged rather than encoded in the exit code: the
    /// `isa-debug-exit` device is one byte wide and QEMU mangles even that (see
    /// [`debug_exit`]), so there is no room for a `(set, code)` pair. The
    /// console is the channel that can carry it, and on this platform the
    /// console is the primary output anyway.
    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        crate::serial_println!("terminate: reason set {reason_set:#X}, code {reason_code:#X}");
        debug_exit(DEBUG_EXIT_FAILURE)
    }

    fn wake_many(_mutex: &core::sync::atomic::AtomicU32, _n: usize) -> Result<usize, Errno> {
        unimplemented!()
    }

    fn block_or_maybe_timeout(
        _mutex: &core::sync::atomic::AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        unimplemented!()
    }

    fn send_ip_packet(_packet: &[u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, Errno> {
        unimplemented!("virtio-net is post-milestone-1")
    }

    /// Unreachable on KVM: there is no lower VTL to switch back to.
    fn switch(_result: u64) -> ! {
        unreachable!("no VTL0 peer exists in a plain KVM guest")
    }
}

// ---------------------------------------------------------------------------
// Cryptographic RNG.
//
// Structurally this mirrors `LvbsCrng` in `host/lvbs/mod.rs`: a ChaCha20 stream
// seeded from RDRAND and periodically reseeded from RDRAND mixed with its own
// current state, with a backoff when RDRAND is temporarily dry.
//
// The one deliberate difference is the seed input. LVBS folds in the platform
// root key, which a VBS platform provisions and which survives reboot. Nothing
// provisions such a key here *yet* -- the intended source is a TPM-backed key,
// see `DerivedKeyProvider` below -- so the seed is RDRAND alone. That leaves
// reboot-persistent key derivation unavailable for now, but does not weaken the
// CRNG itself, whose security rests on RDRAND either way. When the TPM path
// lands, folding its key in here would make the stream reproducible across a
// reboot only if that is ever wanted; it is not required for the CRNG.
//
// The two implementations are duplicated rather than shared because their
// modules are `cfg`-exclusive, and hoisting the common part into a shared
// module would relocate LVBS symbols for no behavioural gain. Worth folding
// together if a third host ever appears.
// ---------------------------------------------------------------------------

type CrngSeed = <rand_chacha::ChaCha20Rng as SeedableRng>::Seed;

const CRNG_RESEED_INTERVAL_BYTES: usize = 1024 * 1024;
const CRNG_RESEED_BACKOFF_BYTES: usize = 64 * 1024;
const CRNG_RESEED_STATE_BYTES: usize = 32;
const RDRAND_RETRY_ATTEMPTS: u32 = 10;

/// `CPUID.1:ECX` bit 30: RDRAND is implemented.
const CPUID_ECX_RDRAND: u32 = 1 << 30;

struct KvmCrng {
    random: rand_chacha::ChaCha20Rng,
    bytes_until_reseed: usize,
    reseed_counter: usize,
}

impl KvmCrng {
    fn new(rdrand_seed: CrngSeed) -> Self {
        Self {
            random: rand_chacha::ChaCha20Rng::from_seed(crng_seed_from_rdrand(rdrand_seed)),
            bytes_until_reseed: CRNG_RESEED_INTERVAL_BYTES,
            reseed_counter: 0,
        }
    }

    fn fill_bytes(&mut self, mut buf: &mut [u8], rdrand_seed: impl Fn() -> Option<CrngSeed>) {
        while !buf.is_empty() {
            let len = buf.len().min(self.bytes_until_reseed);
            let (chunk, rest) = buf.split_at_mut(len);
            self.random.fill_bytes(chunk);
            buf = rest;
            self.bytes_until_reseed -= len;

            if self.bytes_until_reseed == 0 {
                match rdrand_seed() {
                    Some(seed) => self.reseed(seed),
                    None => self.bytes_until_reseed = CRNG_RESEED_BACKOFF_BYTES,
                }
            }
        }
    }

    fn reseed(&mut self, rdrand_seed: CrngSeed) {
        self.reseed_counter += 1;
        let mut current_state = Zeroizing::new([0u8; CRNG_RESEED_STATE_BYTES]);
        self.random.fill_bytes(&mut *current_state);
        self.random = rand_chacha::ChaCha20Rng::from_seed(crng_reseed_from_rdrand_and_state(
            rdrand_seed,
            self.reseed_counter,
            &current_state,
        ));
        self.bytes_until_reseed = CRNG_RESEED_INTERVAL_BYTES;
    }
}

/// Fills `buf` with cryptographically secure random bytes.
///
/// Exposed as a free function so it can be exercised before a [`KvmGuest`]
/// exists: constructing one needs the heap, which is not up until the PVH
/// memory map is parsed.
///
/// # Panics
///
/// Panics if RDRAND is unavailable or fails to produce a seed on first use.
/// There is no weaker fallback worth having: silently degrading a CRNG is how
/// key material becomes predictable.
pub fn fill_bytes_crng(buf: &mut [u8]) {
    static RANDOM: spin::mutex::SpinMutex<Option<KvmCrng>> = spin::mutex::SpinMutex::new(None);

    let mut random = RANDOM.lock();
    random
        .get_or_insert_with(|| {
            assert!(rdrand_supported(), "CPU does not support RDRAND");
            KvmCrng::new(rdrand_seed().expect("RDRAND unavailable during CRNG initialization"))
        })
        .fill_bytes(buf, rdrand_seed);
}

impl litebox::platform::CrngProvider for KvmGuest {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        fill_bytes_crng(buf);
    }
}

/// Length of the platform root key, in bytes.
///
/// Defined here rather than imported from `litebox_common_lvbs::PRK_LEN`, which
/// is the same value (32): that crate is an optional dependency gated on
/// `host_lvbs`, and pulling an LVBS-only crate into the KVM build to share a
/// constant would couple two unrelated roots of trust for no benefit. It is
/// also exactly SHA-256's output length, which is what actually fixes it.
const PRK_LEN: usize = 32;

/// The ASCII sentence the development platform root key is derived from.
///
/// The key is `SHA-256` of exactly these bytes and nothing else. It is spelled
/// out here so that the value is reproducible by anybody with a shell, and so
/// that it cannot be mistaken for a secret: a secret that is printed in the
/// source of a public repository is not one. Deriving it from a documented
/// constant rather than from invented-looking entropy is the whole point --
/// a plausible-looking 32-byte literal would read as though somebody had
/// generated it, and somebody eventually would have trusted it.
const DEV_PRK_DERIVATION_STRING: &[u8] =
    b"litebox-kvm development platform root key v1 -- NOT A SECRET";

/// The emulated platform root key, installed by
/// [`install_development_platform_root_key`].
///
/// Deliberately mirrors `host::lvbs`'s `PRK_ONCE`, including the absence of a
/// raw getter: there is no `get_platform_root_key` here either, so the only
/// way to reach the key material is through [`litebox::platform::DerivedKeyProvider::derive_key`]
/// with a shim-supplied KDF. That property is worth keeping even for a key
/// with no security value, because the day it is replaced by a real one the
/// call sites must already be correct.
static PRK_ONCE: spin::Once<[u8; PRK_LEN]> = spin::Once::new();

/// Installs a **fake** platform root key that emulates what a vTPM would give
/// us, and says so on the console.
///
/// # What this stands in for
///
/// LVBS gets its PRK from VBS, which provisions it and re-provisions the same
/// value after a reboot. The equivalent here would be a key sealed to a TPM 2.0
/// device -- QEMU can attach one with `-tpmdev emulator` backed by swtpm. That
/// path does not exist yet, so this manufactures the key instead.
///
/// # What it does and does not satisfy
///
/// It satisfies the *shape* of the contract and none of the security. The
/// contract `DerivedKeyProvider` callers rely on is "the same key comes back
/// after a reboot", and a constant compiled into the image satisfies that
/// exactly: it is stable across reboots, across guests, and across machines.
/// What it does not have is any of the reason that property is worth anything.
/// The key is public, identical on every LiteBox-on-KVM guest ever built from
/// this source, and rooted in nothing. Anything sealed with a key derived from
/// it is sealed against nobody.
///
/// # Why manufacture it at all
///
/// The alternative -- returning `UnsupportedRebootPersistentKey`, which is what
/// this used to do -- is more honest but tests less. `kmpp-ta` under refusal
/// exercises its *error* path and never reaches the code that actually uses a
/// derived key, so the derivation path in `litebox_shim_optee` was untested on
/// this platform. Installing a key moves the TA onto the real path.
///
/// The earlier objection to manufacturing a key still stands: a fabricated key
/// breaks the reboot-persistence guarantee's *meaning* while satisfying its
/// letter, and does so silently. The answer to "silently" is the `WARN` this
/// emits on every boot, not a decision to keep refusing.
///
/// # Why this is not behind a cargo feature
///
/// It would be reasonable to gate it, and it is not gated. The argument:
///
/// * Nothing about this configuration is production. `docs/plans/2026-08-08-litebox-on-kvm-design.md`
///   §7 lists a missing preemption timer (ring-3 code is *trusted not to loop*),
///   absent stack guard pages, and no TLB shootdown. Singling this one item out
///   for a feature gate would imply the others are settled, which is the more
///   dangerous message.
/// * A feature that must be enabled to run the tests is a feature that gets
///   copied into whatever build eventually ships. An off-by-default flag is
///   exactly as easy to turn on as it is to leave on, and it is invisible in a
///   console log afterwards.
/// * The protection that actually works here is legibility at runtime. A `WARN`
///   on every boot, a key derived from an ASCII string reading
///   `NOT A SECRET`, and this doc comment cannot be missed by anybody reading a
///   boot log or the source. A cfg flag can be.
/// * When the TPM path lands, this is deleted outright. A feature gate would be
///   a second thing to delete and a third state to reason about in the interim.
///
/// Calling this more than once is harmless and installs nothing the second
/// time, matching `spin::Once`.
pub fn install_development_platform_root_key() {
    PRK_ONCE.call_once(|| {
        // Loud on purpose, and unconditional: this is the only runtime signal
        // that the guest's sealed storage is sealed against nobody.
        litebox_util_log::warn!(
            "prk        installing a DEVELOPMENT platform root key with NO SECURITY VALUE"
        );
        litebox_util_log::warn!(
            "prk        it is SHA-256 of a fixed string in host/kvm/mod.rs, public and identical \
             on every LiteBox-on-KVM guest; anything sealed with a key derived from it is \
             sealed against nobody"
        );
        litebox_util_log::warn!(
            "prk        a real deployment needs a TPM-sealed key (QEMU -tpmdev emulator + swtpm); \
             until then this guest is a test vehicle, not a deployment"
        );
        let prk: [u8; PRK_LEN] = sha2::Sha256::new()
            .chain_update(DEV_PRK_DERIVATION_STRING)
            .finalize()
            .into();
        prk
    });
}

/// Reboot-persistent key derivation, rooted in a development key with no
/// security value.
///
/// Mirrors `host::lvbs`'s implementation exactly, including the insistence that
/// the shim supply the KDF: the raw PRK never leaves this module. The only
/// difference is where the key came from, which is
/// [`install_development_platform_root_key`] and its warning.
///
/// If that function has not been called -- an embedded or unit-test path that
/// skips the runner's boot sequence -- this still returns
/// `UnsupportedRebootPersistentKey` rather than deriving from nothing.
impl litebox::platform::DerivedKeyProvider for KvmGuest {
    fn derive_key<E>(
        &self,
        kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(prk) = PRK_ONCE.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        match kdf {
            None => Err(litebox::platform::DerivedKeyError::ShimKDFRequired),
            Some(kdf) => Ok(kdf(prk, params)?),
        }
    }
}

/// Returns whether the CPU implements RDRAND.
///
/// Public so a caller can tell "no hardware entropy source on this machine"
/// apart from "the CRNG is broken" *before* asking for bytes. Asking for bytes
/// without it is still correct and still panics; this only lets a diagnostic
/// avoid provoking that panic deliberately.
pub fn rdrand_supported() -> bool {
    let features = core::arch::x86_64::__cpuid_count(1, 0);
    features.ecx & CPUID_ECX_RDRAND != 0
}

/// Draws a full ChaCha20 seed from RDRAND, retrying a bounded number of times
/// per word. Returns `None` if the hardware entropy source stays dry, which is
/// a transient condition under load rather than a fault.
fn rdrand_seed() -> Option<CrngSeed> {
    let mut seed = CrngSeed::default();
    for chunk in seed.chunks_mut(8) {
        let mut word = 0;
        let mut ok = false;
        for _ in 0..RDRAND_RETRY_ATTEMPTS {
            // SAFETY: RDRAND support is asserted before the first call to this
            // function. A false carry flag means random data is temporarily
            // unavailable, not that the instruction faulted.
            if unsafe { core::arch::x86_64::_rdrand64_step(&mut word) } == 1 {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok {
            return None;
        }
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    Some(seed)
}

fn crng_seed_from_rdrand(rdrand_seed: CrngSeed) -> CrngSeed {
    sha2::Sha256::new()
        .chain_update(b"litebox-kvm-crng-seed-v1")
        .chain_update(rdrand_seed)
        .finalize()
        .into()
}

fn crng_reseed_from_rdrand_and_state(
    rdrand_seed: CrngSeed,
    reseed_counter: usize,
    current_state: &[u8; CRNG_RESEED_STATE_BYTES],
) -> CrngSeed {
    sha2::Sha256::new()
        .chain_update(b"litebox-kvm-crng-reseed-v1")
        .chain_update(rdrand_seed)
        .chain_update(reseed_counter.to_le_bytes())
        .chain_update(current_state)
        .finalize()
        .into()
}
