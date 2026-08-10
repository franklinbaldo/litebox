// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A TSC-based monotonic clock for a plain KVM/QEMU guest.
//!
//! A KVM guest has no Hyper-V partition reference counter, so the only cheap
//! monotonic counter available is the TSC. The TSC counts at a fixed rate on
//! any CPU with the invariant-TSC feature, but *what* that rate is has to be
//! discovered; there is no architectural "read the TSC frequency" instruction.
//!
//! Sources are tried in *descending order of authority* -- how directly each
//! one describes the rate the TSC actually advances at in this guest -- and
//! the first that yields a frequency passing `plausible` wins. Which one won
//! is logged at boot.
//!
//! 1. **KVM pvclock** (MSR `0x4b564d01`). The hypervisor publishes the exact
//!    TSC-to-nanoseconds factors it wants the guest to use. This is the
//!    scaling KVM genuinely applies, so it stays correct under TSC scaling and
//!    across migration, where every CPUID answer below can be stale. Requires
//!    `KVM_FEATURE_CLOCKSOURCE2`, so it is unavailable under TCG.
//! 2. **KVM paravirt CPUID leaf `0x4000_0010`** (TSC kHz). Also KVM-supplied,
//!    but a static kHz value read once: it is a snapshot, not a live
//!    conversion, so TSC scaling or a migration can invalidate it. QEMU does
//!    not advertise this leaf at all in many configurations.
//! 3. **Intel CPUID leaves `0x15`/`0x16`.** Leaf `0x15` (TSC / core-crystal
//!    ratio) then leaf `0x16` (processor base frequency, rounded to a whole
//!    MHz). These describe the *CPU model*, not the guest's TSC scaling, so a
//!    hypervisor that scales the TSC leaves them wrong. They are also
//!    Intel-only and *not implemented on AMD*, so on an AMD host under QEMU
//!    neither answers.
//! 4. **i8254 PIT calibration.** Count TSC ticks across a gated interval of
//!    the PIT, whose 1.193182 MHz input is fixed by the hardware definition.
//!
//! The ordering is deliberately by correctness, not by cost. pvclock costs an
//! MSR write and a page mapping where a CPUID read is nearly free, but
//! `discover` probes lazily: a source that succeeds means every later one is
//! never run, so the cheap sources only ever pay for themselves when the
//! authoritative one is absent. Linux orders the same way -- `kvmclock_init`
//! installs `kvm_get_tsc_khz` as `x86_platform.calibrate_tsc` before the
//! CPUID-based calibration is consulted.
//!
//! Source 4 is a *measurement against a fixed reference*, not a guess. That
//! distinction matters: hardcoding "assume 2 GHz" would produce a clock that
//! is confidently wrong, whereas counting TSC ticks against a crystal whose
//! rate is defined by the i8254's specification produces a real answer whose
//! only error is sampling noise. Linux calibrates the same way, in
//! `quick_pit_calibrate()`, for exactly the same reason. It is last only
//! because it costs ~55 ms of boot time and is less precise than being told:
//! it is the universal fallback, the one source that needs nothing of the
//! hypervisor or the CPU model.
//!
//! If every source fails, this module panics naming each one and what it
//! returned. Falling back to a fabricated frequency would produce a clock that
//! looks like it works and silently reports wrong durations.
//!
//! # The out-of-range CPUID hazard
//!
//! Every CPUID query below checks the relevant maximum-leaf value first.
//! CPUID does *not* return zero for an unsupported leaf: it returns the
//! highest supported leaf's data. Querying leaf `0x15` on a CPU whose maximum
//! standard leaf is `0xd` therefore yields leaf `0xd`'s contents, which are
//! non-zero and look exactly like a valid crystal ratio. Observed in practice
//! under `qemu -cpu max`, which reported `eax=0x21f ebx=0x240 ecx=0xa88` for
//! leaf `0x15` -- aliased garbage that would have calibrated the clock to a
//! fabricated frequency. The max-leaf guards are load-bearing; do not remove
//! them.

use crate::arch::instrs::wrmsr;
use core::arch::x86_64::{__cpuid_count as cpuid_count, _rdtsc};

/// CPUID standard feature-information leaf.
const CPUID_FEATURE_INFO: u32 = 1;
/// `CPUID.1:ECX` bit 31: running under a hypervisor. Architecturally reserved
/// on bare metal, so it is the gate for the `0x4000_0000` leaf range.
const CPUID_ECX_HYPERVISOR: u32 = 1 << 31;
/// CPUID leaf 0: `EAX` is the highest supported standard leaf.
const CPUID_MAX_STANDARD_LEAF: u32 = 0;
/// TSC / core-crystal-clock ratio leaf.
const CPUID_TSC_RATIO_LEAF: u32 = 0x15;
/// Processor frequency information leaf.
const CPUID_PROC_FREQ_LEAF: u32 = 0x16;
/// Base of the hypervisor CPUID range; `EAX` is the highest supported leaf in it.
const CPUID_HYPERVISOR_BASE: u32 = 0x4000_0000;
/// KVM's interface signature, returned in `EBX`/`ECX`/`EDX` of leaf
/// `0x4000_0000`: the twelve bytes `"KVMKVMKVM\0\0\0"`.
///
/// The `0x4000_00xx` range is shared by every hypervisor, and the meaning of
/// every leaf in it is vendor specific. Nothing below may be read as a KVM
/// value until these three registers say KVM; see [`kvm_max_leaf`].
const CPUID_KVM_SIGNATURE_EBX: u32 = 0x4b4d_564b;
const CPUID_KVM_SIGNATURE_ECX: u32 = 0x564b_4d56;
const CPUID_KVM_SIGNATURE_EDX: u32 = 0x0000_004d;
/// Hypervisor feature leaf; `EAX` is a bitmap of `KVM_FEATURE_*`.
const CPUID_HYPERVISOR_FEATURES: u32 = 0x4000_0001;
/// KVM paravirt leaf reporting the TSC frequency in kHz.
const CPUID_KVM_TSC_FREQ_LEAF: u32 = 0x4000_0010;
/// `KVM_FEATURE_CLOCKSOURCE2`: the `0x4b564d0x` pvclock MSRs are implemented.
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3;
/// `MSR_KVM_SYSTEM_TIME_NEW`: guest physical address of the pvclock page,
/// with bit 0 set to enable hypervisor updates.
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;

/// Lowest frequency accepted from any source, in Hz.
///
/// Nothing that can run this code has a 100 MHz TSC. A result this low means
/// the source misreported or the calibration was disturbed, not that the CPU
/// is slow, so it is rejected and the next source tried.
const MIN_PLAUSIBLE_HZ: u64 = 100_000_000;

/// Highest frequency accepted from any source, in Hz.
const MAX_PLAUSIBLE_HZ: u64 = 100_000_000_000;

/// Fixed-point shift used by the TSC-to-nanoseconds conversion.
///
/// 32 keeps `mult` comfortably inside `u64` for any plausible TSC rate (it is
/// `10^9 * 2^32 / hz`, so ~1.7e9 at 2.5 GHz) while bounding the truncation
/// error of `mult` itself to under one part in `2^31`.
const SCALE_SHIFT: u32 = 32;

/// Returns whether a candidate frequency is worth trusting.
fn plausible(hz: u64) -> bool {
    (MIN_PLAUSIBLE_HZ..=MAX_PLAUSIBLE_HZ).contains(&hz)
}

/// The discovered TSC rate and the conversion factor derived from it.
#[derive(Clone, Copy)]
struct TscScale {
    /// TSC ticks per second.
    hz: u64,
    /// `10^9 * 2^SCALE_SHIFT / hz`: multiply a tick count by this and shift
    /// right by [`SCALE_SHIFT`] to get nanoseconds.
    mult: u64,
    /// Which source supplied [`Self::hz`]. Logged at boot so the path taken on
    /// a given machine is visible rather than guessed at.
    source: &'static str,
}

/// Computed once on first use; a plain `Once` needs no allocation.
static TSC_SCALE: spin::Once<TscScale> = spin::Once::new();

// ---------------------------------------------------------------------------
// Sources 2 and 3: CPUID.
//
// Ordered after pvclock below; see the module docs. Kept first in file order
// because `kvm_max_leaf` and `hypervisor_present` live here and the pvclock
// section depends on them.
// ---------------------------------------------------------------------------

/// Reads the TSC frequency in Hz from the KVM paravirt CPUID leaf.
///
/// Returns `None` if the hypervisor is absent or is not KVM, if the KVM leaf
/// range does not extend to the frequency leaf, or if the leaf reports zero.
fn kvm_paravirt_hz() -> Option<u64> {
    if kvm_max_leaf()? < CPUID_KVM_TSC_FREQ_LEAF {
        return None;
    }

    let khz = cpuid_count(CPUID_KVM_TSC_FREQ_LEAF, 0).eax;
    (khz != 0).then(|| u64::from(khz) * 1_000)
}

/// Reads the TSC frequency in Hz from leaf `0x15`.
///
/// `EAX` is the ratio's denominator, `EBX` its numerator and `ECX` the
/// core-crystal frequency in Hz, giving `hz = ECX * EBX / EAX`. Returns `None`
/// unless all three are populated; a zero `ECX` (common under virtualisation)
/// makes the ratio unusable on its own.
fn crystal_ratio_hz() -> Option<u64> {
    if cpuid_count(CPUID_MAX_STANDARD_LEAF, 0).eax < CPUID_TSC_RATIO_LEAF {
        return None;
    }

    let leaf = cpuid_count(CPUID_TSC_RATIO_LEAF, 0);
    let (denominator, numerator, crystal_hz) = (leaf.eax, leaf.ebx, leaf.ecx);
    if denominator == 0 || numerator == 0 || crystal_hz == 0 {
        return None;
    }

    // Widened before multiplying: `crystal_hz * numerator` overflows 32 bits
    // for any realistic crystal.
    Some(u64::from(crystal_hz) * u64::from(numerator) / u64::from(denominator))
}

/// Reads the processor base frequency in Hz from leaf `0x16`.
///
/// `EAX` holds it in MHz. This is the nominal base clock, which equals the TSC
/// rate on invariant-TSC parts, but rounded to a whole MHz.
fn base_frequency_hz() -> Option<u64> {
    if cpuid_count(CPUID_MAX_STANDARD_LEAF, 0).eax < CPUID_PROC_FREQ_LEAF {
        return None;
    }

    let base_mhz = cpuid_count(CPUID_PROC_FREQ_LEAF, 0).eax;
    (base_mhz != 0).then(|| u64::from(base_mhz) * 1_000_000)
}

/// Returns whether `CPUID.1:ECX` reports the hypervisor-present bit.
fn hypervisor_present() -> bool {
    cpuid_count(CPUID_FEATURE_INFO, 0).ecx & CPUID_ECX_HYPERVISOR != 0
}

/// Returns the highest `0x4000_00xx` leaf, but *only if the hypervisor is KVM*.
///
/// The hypervisor CPUID range is not architectural and is not owned by any one
/// vendor: every hypervisor puts its own leaves there, and the same leaf number
/// means different things to different ones. Leaf `0x4000_0000` exists to say
/// whose interpretation applies, and it must be consulted before anything in
/// the range is read as a KVM value.
///
/// Skipping that check is not a theoretical problem. Under Hyper-V, leaf
/// `0x4000_0001` `EAX` is the interface signature `"Hv#1"` = `0x3123_7648`, and
/// bit 3 of that is set -- which is exactly the bit we read as
/// `KVM_FEATURE_CLOCKSOURCE2`. Believing it leads straight to
/// `wrmsr(0x4b564d01)`, a KVM MSR Hyper-V does not implement, which `#GP`s;
/// with no IDT this early that is a silent triple fault.
///
/// A non-KVM hypervisor therefore means "no KVM paravirt clock sources", and
/// discovery falls through to PIT calibration, which works everywhere.
fn kvm_max_leaf() -> Option<u32> {
    // The `0x4000_00xx` range is architecturally reserved on bare metal, where
    // CPUID would alias it to the highest standard leaf's contents rather than
    // returning zero, so the hypervisor-present bit gates the query itself.
    if !hypervisor_present() {
        return None;
    }

    let leaf = cpuid_count(CPUID_HYPERVISOR_BASE, 0);
    let is_kvm = leaf.ebx == CPUID_KVM_SIGNATURE_EBX
        && leaf.ecx == CPUID_KVM_SIGNATURE_ECX
        && leaf.edx == CPUID_KVM_SIGNATURE_EDX;

    is_kvm.then_some(leaf.eax)
}

// ---------------------------------------------------------------------------
// Source 1: KVM pvclock.
// ---------------------------------------------------------------------------

/// KVM's `struct pvclock_vcpu_time_info`, the layout the hypervisor writes
/// into the page handed to it via [`MSR_KVM_SYSTEM_TIME_NEW`].
///
/// Over-aligned to 64 bytes so the whole structure is guaranteed to sit inside
/// one page, which is what the hypervisor requires of the address it is given.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct PvclockTimeInfo {
    /// Odd while the hypervisor is mid-update; used as a seqlock.
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    /// Multiplier in the hypervisor's TSC-to-nanoseconds conversion.
    tsc_to_system_mul: u32,
    /// Signed pre-shift applied to the TSC delta before multiplying.
    tsc_shift: i8,
    flags: u8,
    pad: [u8; 2],
}

/// Wrapper giving [`PVCLOCK`] interior mutability. The hypervisor writes to
/// this memory behind Rust's back, so every access is volatile.
struct PvclockCell(core::cell::UnsafeCell<PvclockTimeInfo>);

// SAFETY: The contents are only ever touched through volatile reads of a raw
// pointer, and the hypervisor is disabled again before `pvclock_hz`
// returns, so no reference into the cell outlives the window in which the
// hypervisor may write.
unsafe impl Sync for PvclockCell {}

/// The page the hypervisor publishes pvclock data into.
///
/// A static rather than an allocation: there is no heap this early, and none
/// is needed for 64 bytes.
static PVCLOCK: PvclockCell = PvclockCell(core::cell::UnsafeCell::new(PvclockTimeInfo {
    version: 0,
    pad0: 0,
    tsc_timestamp: 0,
    system_time: 0,
    tsc_to_system_mul: 0,
    tsc_shift: 0,
    flags: 0,
    pad: [0; 2],
}));

/// Bounded retries for the pvclock seqlock. The hypervisor updates this
/// structure rarely, so more than a couple of collisions means something is
/// wrong and falling through to the next source beats spinning.
const PVCLOCK_READ_ATTEMPTS: u32 = 16;

/// Reads the TSC frequency in Hz from the KVM pvclock page.
///
/// The hypervisor's conversion is
/// `ns = ((tsc << tsc_shift) * tsc_to_system_mul) >> 32` (with a negative
/// `tsc_shift` meaning a right shift), so one TSC tick is
/// `tsc_to_system_mul * 2^tsc_shift / 2^32` nanoseconds and the frequency is
/// `10^9 * 2^(32 - tsc_shift) / tsc_to_system_mul`.
///
/// Returns `None` if the hypervisor is not KVM, or is KVM but lacks
/// `KVM_FEATURE_CLOCKSOURCE2` (either way the MSR must not be written -- there
/// is no IDT this early, and a `#GP` would triple-fault), or if the hypervisor
/// never publishes a stable version.
fn pvclock_hz() -> Option<u64> {
    if !kvm_clocksource2_supported() {
        return None;
    }

    let page = PVCLOCK.0.get();
    // The runner maps the kernel image at `VA = PA + KERNEL_OFFSET`, which is
    // the same window `MemoryProvider::pa_to_va` assumes, so inverting it
    // gives the guest physical address the hypervisor needs.
    let guest_phys_addr = (page as u64).wrapping_sub(crate::KERNEL_OFFSET);

    // Bit 0 enables hypervisor updates into the page.
    wrmsr(MSR_KVM_SYSTEM_TIME_NEW, guest_phys_addr | 1);

    let mut result = None;
    for _ in 0..PVCLOCK_READ_ATTEMPTS {
        // SAFETY: `page` points at a live, correctly aligned static. The reads
        // are volatile because the hypervisor mutates this memory
        // asynchronously, and the version seqlock below is what makes the
        // triple consistent.
        let (version_before, mul, shift) = unsafe {
            let version_before = (&raw const (*page).version).read_volatile();
            let mul = (&raw const (*page).tsc_to_system_mul).read_volatile();
            let shift = (&raw const (*page).tsc_shift).read_volatile();
            (version_before, mul, shift)
        };
        // SAFETY: As above.
        let version_after = unsafe { (&raw const (*page).version).read_volatile() };

        // An odd version means an update was in flight; a changed version
        // means one landed while we were reading. Version zero means the
        // hypervisor has not published anything at all.
        if version_before == version_after && version_before != 0 && version_before % 2 == 0 {
            result = frequency_from_pvclock(mul, shift);
            break;
        }
        core::hint::spin_loop();
    }

    // Stop the hypervisor writing into our page: the factors are constant for
    // the life of the guest, so there is no reason to keep a live channel into
    // a static after taking them.
    wrmsr(MSR_KVM_SYSTEM_TIME_NEW, 0);

    result
}

/// Converts pvclock's `tsc_to_system_mul` / `tsc_shift` pair into Hz.
fn frequency_from_pvclock(mul: u32, shift: i8) -> Option<u64> {
    if mul == 0 {
        return None;
    }
    // `shift` is small in practice (-3..=1); bound it anyway so the shift
    // below cannot overflow regardless of what the hypervisor publishes.
    let shift_amount = i32::try_from(SCALE_SHIFT)
        .ok()?
        .checked_sub(i32::from(shift))?;
    if !(0..=96).contains(&shift_amount) {
        return None;
    }
    // Non-negative by the range check above, so this cannot fail.
    let numerator = 1_000_000_000u128.checked_shl(u32::try_from(shift_amount).ok()?)?;
    u64::try_from(numerator / u128::from(mul)).ok()
}

/// Returns whether the hypervisor is KVM *and* advertises
/// `KVM_FEATURE_CLOCKSOURCE2`. The vendor half is load-bearing: see
/// [`kvm_max_leaf`] for the Hyper-V aliasing that makes reading this bit
/// without it a triple fault.
fn kvm_clocksource2_supported() -> bool {
    let Some(max_leaf) = kvm_max_leaf() else {
        return false;
    };
    if max_leaf < CPUID_HYPERVISOR_FEATURES {
        return false;
    }
    cpuid_count(CPUID_HYPERVISOR_FEATURES, 0).eax & KVM_FEATURE_CLOCKSOURCE2 != 0
}

// ---------------------------------------------------------------------------
// Source 4: i8254 PIT calibration.
// ---------------------------------------------------------------------------

/// The i8254's input clock, in Hz.
///
/// This is not an assumption: 1.193182 MHz (the NTSC colourburst frequency
/// divided by three) is fixed by the PC/AT hardware definition and is what
/// every PIT implementation, emulated or not, counts at.
const PIT_INPUT_HZ: u64 = 1_193_182;

/// PIT mode/command register.
const PIT_COMMAND_PORT: u16 = 0x43;
/// PIT channel 2 data register.
const PIT_CHANNEL2_PORT: u16 = 0x42;
/// NMI status and control ("speaker") port: bit 0 is channel 2's GATE input,
/// bit 1 the speaker driver, bit 5 channel 2's OUT level.
const PIT_GATE_PORT: u16 = 0x61;
const PIT_GATE_ENABLE: u8 = 1 << 0;
const PIT_SPEAKER_ENABLE: u8 = 1 << 1;
const PIT_CHANNEL2_OUTPUT: u8 = 1 << 5;

/// Channel 2, access low byte then high byte, mode 0 (interrupt on terminal
/// count), binary counting.
const PIT_MODE0_CHANNEL2: u8 = 0b1011_0000;

/// Counter loaded for the calibration interval. The full 16-bit range gives
/// the longest single-shot interval the PIT can produce, 65535 / 1.193182 MHz
/// = 54.9 ms, which keeps the relative cost of the sampling overhead low.
const PIT_CALIBRATION_COUNT: u16 = 0xFFFF;

/// Upper bound on spins waiting for the PIT to reach terminal count.
///
/// Generous enough never to trip on a working PIT, but bounded so a machine
/// with no PIT at all falls through to the panic instead of hanging forever.
const PIT_WAIT_SPINS: u64 = 1_000_000_000;

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Reading the PIT and NMI-control ports has no memory effects.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    }
    value
}

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: The ports written here are the PIT's own registers and channel
    // 2's gate. Channel 2 drives only the PC speaker, which is left disabled
    // throughout, so nothing else in the system depends on it.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Runs one gated PIT interval, returning the TSC ticks that elapsed across it
/// and the interval's exact nominal duration in nanoseconds.
///
/// Channel 2 is used rather than channel 0 because its GATE is software
/// controlled (port `0x61` bit 0) and its OUT is software readable (bit 5),
/// so the interval can be started and observed without any interrupt
/// plumbing -- which matters here, as there is no IDT yet.
///
/// Returns `None` if the PIT never reaches terminal count.
fn pit_gated_interval() -> Option<(u64, u64)> {
    // Speaker off, gate low: channel 2 is held reset while it is programmed.
    let gate_base = (inb(PIT_GATE_PORT) & !PIT_SPEAKER_ENABLE) & !PIT_GATE_ENABLE;
    outb(PIT_GATE_PORT, gate_base);

    outb(PIT_COMMAND_PORT, PIT_MODE0_CHANNEL2);
    outb(PIT_CHANNEL2_PORT, (PIT_CALIBRATION_COUNT & 0xff) as u8);
    outb(PIT_CHANNEL2_PORT, (PIT_CALIBRATION_COUNT >> 8) as u8);

    // Gate high starts the count. In mode 0 OUT went low when the count was
    // loaded and rises again at terminal count, which is what we poll for.
    outb(PIT_GATE_PORT, gate_base | PIT_GATE_ENABLE);

    let start = read_tsc();

    let mut reached_terminal_count = false;
    for _ in 0..PIT_WAIT_SPINS {
        if inb(PIT_GATE_PORT) & PIT_CHANNEL2_OUTPUT != 0 {
            reached_terminal_count = true;
            break;
        }
    }

    let end = read_tsc();

    // Leave the gate as we found it.
    outb(PIT_GATE_PORT, gate_base);

    if !reached_terminal_count {
        return None;
    }

    let nominal_nanos = u64::from(PIT_CALIBRATION_COUNT) * 1_000_000_000 / PIT_INPUT_HZ;
    Some((end.wrapping_sub(start), nominal_nanos))
}

/// Measures the TSC frequency in Hz against the PIT.
fn pit_calibrated_hz() -> Option<u64> {
    let (tsc_delta, nominal_nanos) = pit_gated_interval()?;
    if tsc_delta == 0 || nominal_nanos == 0 {
        return None;
    }
    u64::try_from(u128::from(tsc_delta) * 1_000_000_000 / u128::from(nominal_nanos)).ok()
}

/// Runs one gated PIT interval and returns its exact nominal duration in
/// nanoseconds, discarding the TSC reading.
///
/// Exposed so callers can bracket a known-length delay with two [`crate::Instant`]s
/// and check the two clocks against each other. The PIT is an independent
/// reference, so agreement between them is real evidence that the TSC scaling
/// is right -- much stronger than the TSC agreeing with itself.
///
/// Returns `None` if the PIT is unavailable.
pub fn pit_reference_interval_nanos() -> Option<u64> {
    pit_gated_interval().map(|(_, nominal_nanos)| nominal_nanos)
}

// ---------------------------------------------------------------------------
// Discovery and the public clock.
// ---------------------------------------------------------------------------

/// A named TSC-frequency source: a label for the boot log and a probe that
/// returns the frequency in Hz, or `None` if this machine does not offer it.
type FrequencySource = (&'static str, fn() -> Option<u64>);

/// Discovers the TSC frequency and derives the nanosecond conversion factor.
///
/// # Panics
///
/// Panics if no source yields a plausible frequency, reporting what each one
/// returned. Guessing instead would yield a clock that never fails loudly and
/// is wrong by an unknown factor.
fn discover() -> TscScale {
    // Function pointers, not an array of already-computed `Option<u64>`: an
    // array literal evaluates every element before the loop runs, so the
    // ~55 ms PIT calibration and the pvclock MSR enable/disable pair would be
    // paid on every boot even when CPUID answered first. Only the *selection*
    // would be ordered, not the work.
    //
    // Ordered by authority, not by cost; see the module docs. pvclock is the
    // conversion KVM actually applies, so it survives TSC scaling and
    // migration; `0x4000_0010` is KVM-supplied but a static snapshot that
    // scaling can invalidate; `0x15`/`0x16` describe the CPU model and know
    // nothing of scaling; the PIT is a real measurement and works everywhere,
    // so it is the universal last resort.
    let candidates: [FrequencySource; 5] = [
        ("KVM pvclock (MSR 0x4b564d01)", pvclock_hz),
        ("CPUID 0x40000010 (KVM paravirt)", kvm_paravirt_hz),
        ("CPUID 0x15 (core crystal ratio)", crystal_ratio_hz),
        ("CPUID 0x16 (processor base frequency)", base_frequency_hz),
        ("i8254 PIT calibration", pit_calibrated_hz),
    ];

    // What each probe actually returned, recorded as the loop runs.
    //
    // Recorded rather than re-derived on the panic path. Re-calling the probes
    // would report *fresh* answers, not the ones that were rejected: a PIT
    // calibration is a new 55 ms measurement each time, and `pvclock_hz` would
    // enable and disable the pvclock MSR a second time. When the complaint is
    // "these values were implausible", the message has to name the values that
    // were actually judged, or it is evidence about a different run.
    let mut results: [Option<u64>; 5] = [None; 5];

    for (i, (source, probe)) in candidates.into_iter().enumerate() {
        let hz = probe();
        results[i] = hz;
        if let Some(hz) = hz
            && plausible(hz)
        {
            // `hz` passed the plausibility range, so it is non-zero and this
            // can neither divide by zero nor produce a zero `mult`. The
            // plausible floor also keeps the quotient under 2^64: the numerator
            // is 10^9 * 2^32, so any `hz` above 1 fits comfortably.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "bounded by `plausible(hz)`; see above"
            )]
            let mult = ((1_000_000_000u128 << SCALE_SHIFT) / u128::from(hz)) as u64;
            return TscScale { hz, mult, source };
        }
    }

    // Re-read the raw leaves so the message reports what was actually seen
    // rather than merely that nothing worked.
    let max_standard_leaf = cpuid_count(CPUID_MAX_STANDARD_LEAF, 0).eax;
    let leaf_15 = cpuid_count(CPUID_TSC_RATIO_LEAF, 0);
    let leaf_16 = cpuid_count(CPUID_PROC_FREQ_LEAF, 0);
    let hypervisor_present = hypervisor_present();
    let max_hypervisor_leaf = if hypervisor_present {
        cpuid_count(CPUID_HYPERVISOR_BASE, 0).eax
    } else {
        0
    };
    panic!(
        "cannot determine TSC frequency; every source failed or was implausible \
         (accepted range {MIN_PLAUSIBLE_HZ}..={MAX_PLAUSIBLE_HZ} Hz). \
         CPUID: max standard leaf {max_standard_leaf:#x}, \
         hypervisor present {hypervisor_present}, \
         max hypervisor leaf {max_hypervisor_leaf:#x}, \
         KVM signature {is_kvm}, \
         leaf 0x15 eax={:#x} ebx={:#x} ecx={:#x}, leaf 0x16 eax={:#x}. \
         Candidates: pvclock {:?}, 0x40000010 {:?}, 0x15 {:?}, 0x16 {:?}, PIT {:?}. \
         Refusing to guess a frequency",
        leaf_15.eax,
        leaf_15.ebx,
        leaf_15.ecx,
        leaf_16.eax,
        results[0],
        results[1],
        results[2],
        results[3],
        results[4],
        is_kvm = kvm_max_leaf().is_some(),
    );
}

/// Returns the TSC frequency in Hz, discovering it on first call.
///
/// # Panics
///
/// Panics if no source reports a plausible frequency; see `discover`.
pub fn tsc_hz() -> u64 {
    TSC_SCALE.call_once(discover).hz
}

/// Returns a human-readable name for the source that supplied the TSC
/// frequency, for boot logging.
///
/// # Panics
///
/// Panics if no source reports a plausible frequency; see `discover`.
pub fn tsc_source() -> &'static str {
    TSC_SCALE.call_once(discover).source
}

/// Reads the TSC.
///
/// The `lfence` matters: `rdtsc` is not a serializing instruction and may be
/// executed ahead of earlier work, which would let a short interval measure as
/// absurdly small. This bounds it from the front, which is what interval
/// measurement needs.
#[inline]
fn read_tsc() -> u64 {
    // SAFETY: `lfence` and `rdtsc` only order execution and read a counter.
    // `rdtsc` is unconditionally available on x86_64, and CR4.TSD is clear (we
    // never set it), so it does not fault.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        _rdtsc()
    }
}

/// Reads the TSC, converted to nanoseconds since an arbitrary boot-time origin.
///
/// The origin is whatever the TSC happened to read at power-on, so only
/// differences between two readings are meaningful -- which is exactly the
/// contract of [`crate::Instant`].
///
/// # Panics
///
/// Panics on the first call if no source reports a plausible frequency; see
/// `discover`.
pub fn monotonic_nanos() -> u64 {
    let scale = TSC_SCALE.call_once(discover);

    // Widened to `u128` before the multiply: at 2.5 GHz `mult` is ~1.7e9, so
    // `ticks * mult` leaves the 64-bit range after roughly five seconds of
    // uptime. The shift brings the product back into `u64`, where it does not
    // overflow until ~584 years of nanoseconds.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the right shift by SCALE_SHIFT brings the product back into u64; see above"
    )]
    {
        ((u128::from(read_tsc()) * u128::from(scale.mult)) >> SCALE_SHIFT) as u64
    }
}
