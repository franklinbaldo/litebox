// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for a plain KVM/QEMU guest.
//!
//! Unlike LVBS, LiteBox here *is* the kernel: there is no VTL0 peer to delegate
//! to. The security boundary is ring 0 vs ring 3, enforced by page tables,
//! SMEP/SMAP and the syscall gate — a conventional OS threat model rather than
//! a VBS one. `litebox_runner_kvm` establishes that boundary; see the
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
//!
//! ## Cannot exist here
//!
//! Not gaps. These would be wrong to implement, and are deliberately *not*
//! `unimplemented!()` so that they do not read as a to-do list:
//!
//! * [`HostInterface::switch`] is `unreachable!()`. It transfers control to
//!   VTL0, and a plain KVM guest has no VTL0 peer to transfer to. There is no
//!   future in which this gains a body.
//! * `litebox::platform::DerivedKeyProvider` returns
//!   `DerivedKeyError::UnsupportedRebootPersistentKey` rather than panicking.
//!   A plain KVM guest has no platform root key to derive from; returning a
//!   manufactured key would satisfy the signature while silently breaking the
//!   reboot-persistence guarantee callers depend on. `Unsupported` is the
//!   truthful answer, and callers can handle it.
//!
//! ## Absent entirely
//!
//! `litebox::platform::ThreadLocalStorageProvider` and `init_task` are
//! implemented for `LvbsLinuxKernel` but have no `KvmGuest` counterpart — not
//! even a stub. Nothing in the crate demands those bounds on this path yet, so
//! the omission compiles. Neither is LVBS-specific (TLS is just `pcv.tls`), so
//! both are straightforward ports whenever a caller first needs them.
//!
use crate::{Errno, HostInterface, arch::ioport::serial_print_string};
use digest::Digest;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

pub type KvmGuest = crate::LinuxKernel<HostKvmInterface>;

pub struct HostKvmInterface;

// ---------------------------------------------------------------------------
// The heap.
//
// Structurally this mirrors the `alloc` module in `lvbs_impl.rs`: a
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
    /// `lvbs_impl` does the same.
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
// Structurally this mirrors `LvbsCrng` in `lvbs_impl.rs`: a ChaCha20 stream
// seeded from RDRAND and periodically reseeded from RDRAND mixed with its own
// current state, with a backoff when RDRAND is temporarily dry.
//
// The one deliberate difference is the seed input. LVBS folds in the platform
// root key, which a VBS platform provisions and which survives reboot. A plain
// KVM guest has no such key and nothing to derive one from, so the seed here is
// RDRAND alone. That weakens reboot-persistent key derivation -- see
// `DerivedKeyProvider` below, which reports that honestly -- but not the CRNG
// itself, whose security rests on RDRAND either way.
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

/// A KVM guest has no reboot-persistent platform key.
///
/// This is `Unsupported`, not `unimplemented!()`, and the distinction is the
/// point: an unimplemented provider says "this is missing and someone should
/// write it", whereas there is genuinely nothing on a plain KVM guest to root
/// such a key in. LVBS derives its PRK from VBS-provisioned state; the closest
/// equivalents here (vTPM, SEV-SNP key derivation) are not part of this
/// platform. Manufacturing a key from, say, a boot nonce would satisfy the
/// signature while quietly failing the "persistent across reboot" guarantee
/// that callers rely on, so the honest answer is to refuse.
impl litebox::platform::DerivedKeyProvider for KvmGuest {
    fn derive_key<E>(
        &self,
        _kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        _params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey)
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
