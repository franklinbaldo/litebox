// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for a plain KVM/QEMU guest.
//!
//! Unlike LVBS, LiteBox here *is* the kernel: there is no VTL0 peer to delegate
//! to. The security boundary is ring 0 vs ring 3, enforced by page tables,
//! SMEP/SMAP and the syscall gate — a conventional OS threat model rather than
//! a VBS one.
//!
//! Phase 1 note: every method below is still a stub. Real implementations land
//! with the boot path in Phase 2.

use crate::{Errno, HostInterface, arch::ioport::serial_print_string};
use digest::Digest;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroizing;

pub type KvmGuest = crate::LinuxKernel<HostKvmInterface>;

pub struct HostKvmInterface;

/// Phase 1 stub. Phase 2 implements a real page allocator over the memory map
/// handed to us by the PVH firmware entry point.
impl crate::mm::MemoryProvider for KvmGuest {
    /// A plain higher-half offset; nothing VSM-specific about it, so it matches
    /// the LVBS value.
    const GVA_OFFSET: x86_64::VirtAddr = x86_64::VirtAddr::new(crate::GVA_OFFSET);
    /// A plain KVM guest has no memory-encryption bit to set in the PTE.
    const PRIVATE_PTE_MASK: u64 = 0;

    fn mem_allocate_pages(_order: u32) -> Option<*mut u8> {
        unimplemented!("KVM page allocator lands in Phase 2")
    }

    unsafe fn mem_free_pages(_ptr: *mut u8, _order: u32) {
        unimplemented!("KVM page allocator lands in Phase 2")
    }

    unsafe fn mem_fill_pages(_start: usize, _size: usize) {
        unimplemented!("KVM page allocator lands in Phase 2")
    }
}

impl HostInterface for HostKvmInterface {
    fn log(msg: &str) {
        serial_print_string(msg);
    }

    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    unsafe fn free(_addr: usize) {
        unimplemented!("KVM host allocator lands in Phase 2")
    }

    fn exit() -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        unimplemented!("isa-debug-exit lands in Phase 2")
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
