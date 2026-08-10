// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A split virtqueue.
//!
//! A virtqueue is three arrays shared with the device: a descriptor table the
//! driver fills in, an *available* ring the driver publishes descriptor chains
//! through, and a *used* ring the device publishes completions through. The
//! device reads all three by physical address, so every buffer they name has
//! to be physically contiguous and its physical address has to be what is
//! written into them -- not the kernel virtual address the driver holds.
//!
//! This implementation is deliberately the smallest thing that works:
//!
//! - **Polling only.** No interrupts are wired up, so `VIRTQ_USED_F_NO_NOTIFY`
//!   and the event-index feature are both irrelevant; the driver notifies on
//!   every publish and spins on the used ring.
//! - **Single-descriptor chains.** Every buffer submitted is one descriptor.
//!   Chains exist for scatter-gather, and nothing here scatters.
//! - **No indirect descriptors.** `VIRTIO_F_RING_INDIRECT_DESC` is offered by
//!   QEMU and declined; it saves descriptor table space for large chains,
//!   which this does not have.
//!
//! # Memory ordering
//!
//! The device is a concurrent agent reading this memory. Two orderings are
//! load-bearing and are the ones the specification calls out:
//!
//! - The descriptor table and the available ring's entries must be visible
//!   *before* `avail.idx` is bumped, or the device can act on a ring slot that
//!   still holds the previous round's descriptor index.
//! - `used.idx` must be read *before* the used ring entry it makes visible.
//!
//! x86-64's store ordering makes the first of these free in practice and the
//! second nearly so, but the fences are written out regardless: they are also
//! what stops the *compiler* from reordering or eliding these accesses, which
//! is not a hardware property at all.

#![expect(
    clippy::cast_ptr_alignment,
    reason = "every typed cast in this module is from a `Dma` base, which is a whole-page \
              allocation and so aligned for anything; `Dma::new` asserts it"
)]

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

#[cfg(not(test))]
use litebox_platform_lvbs::mm::MemoryProvider as _;
#[cfg(not(test))]
use litebox_platform_multiplex::Platform;

/// `VIRTQ_DESC_F_WRITE`: the buffer is written by the device, i.e. it is a
/// device-to-driver buffer.
pub const DESC_F_WRITE: u16 = 2;

/// One entry of the descriptor table.
///
/// `#[repr(C)]` because the device reads this by offset; the layout is the
/// interface.
#[derive(Clone, Copy)]
#[repr(C)]
struct Desc {
    /// Physical address of the buffer.
    addr: u64,
    len: u32,
    flags: u16,
    /// Index of the next descriptor in the chain, if `DESC_F_NEXT` is set.
    next: u16,
}

/// One entry of the used ring: which chain completed, and how many bytes the
/// device wrote into it.
#[derive(Clone, Copy)]
#[repr(C)]
struct UsedElem {
    /// Index of the head descriptor of the completed chain.
    id: u32,
    /// Bytes written by the device. Zero for a driver-to-device buffer.
    len: u32,
}

/// A page-aligned, physically contiguous, zeroed allocation, remembered with
/// the physical address the device needs.
///
/// The whole point of the type is to carry the physical address alongside the
/// virtual one. A virtqueue's rings and every buffer they name are read by the
/// device by physical address, and the kernel virtual address the driver holds
/// is not it -- writing a VA into a descriptor makes the device read whatever
/// RAM happens to live at that number, which on this platform is far past the
/// end of memory.
pub struct Dma {
    /// Start of the allocation, kept as `*mut u8` because it is a byte buffer
    /// in its own right as well as the base for typed ring accesses.
    ///
    /// Every typed cast below is 4 KiB-aligned by construction --
    /// `mem_allocate_pages` returns whole pages -- which is why they carry an
    /// `expect` for `cast_ptr_alignment` rather than an alignment check.
    va: *mut u8,
    pa: u64,
    /// Usable capacity in bytes: what the allocation was *asked* for, not what
    /// it was rounded up to.
    ///
    /// This is what makes a length check possible at all. `used_elem.len` is
    /// written by the device, and the device is untrusted -- in the two-VM
    /// arrangement it is the normal world -- so a completion may report more
    /// bytes than the buffer can hold. Without a length recorded here, the
    /// safe `pub` [`Self::read_into`] and [`Self::fill`] have nothing to check
    /// against and depend on every caller remembering to clamp, which is a
    /// guarantee no signature expresses. Keeping the capacity with the
    /// allocation moves the check to where the fact lives.
    ///
    /// The requested size rather than the rounded-up one: the rounding to
    /// whole pages is slack, not capacity to be relied on.
    len: usize,
}

impl Dma {
    /// Allocates at least `bytes`, rounded up to a power-of-two number of
    /// pages.
    ///
    /// Where the pages come from is [`Self::allocate`]'s business.
    ///
    /// # Panics
    ///
    /// Panics if the allocation fails.
    fn new(bytes: u64) -> Self {
        let pages = bytes.div_ceil(4096).max(1);
        let order = pages.next_power_of_two().trailing_zeros();
        let (va, pa) = Self::allocate(bytes, order);
        let size = usize::try_from(u64::from(1_u32 << order) * 4096).expect("64-bit target");
        // The device reads this memory before the driver writes every byte of
        // it -- `avail.flags`, the used ring's contents and the tail of the
        // descriptor table are all read while still untouched. Zeroing means
        // it reads defined values rather than whatever the heap last held.
        //
        // SAFETY: `allocate` returned a live, exclusively owned allocation of
        // exactly this size.
        unsafe { core::ptr::write_bytes(va, 0, size) };
        // The typed ring accesses elsewhere in this module cast this pointer
        // to `Desc`, `UsedElem` and `u16`. They are sound because the
        // allocator returns whole pages; assert it rather than believe it.
        assert!(
            (va as usize).is_multiple_of(4096),
            "DMA allocation {va:p} is not page-aligned"
        );
        Self {
            pa,
            va,
            len: usize::try_from(bytes).expect("64-bit target"),
        }
    }

    /// Obtains `1 << order` contiguous, page-aligned pages, and the physical
    /// address the device must be given for them.
    ///
    /// The buddy allocator hands out whole `1 << order` page blocks that are
    /// contiguous in both address spaces, which is exactly the property a
    /// virtqueue needs and the reason nothing smaller-grained is used here.
    ///
    /// # Panics
    ///
    /// Panics if the allocation fails.
    #[cfg(not(test))]
    fn allocate(bytes: u64, order: u32) -> (*mut u8, u64) {
        let va = Platform::mem_allocate_pages(order)
            .unwrap_or_else(|| panic!("out of memory allocating {bytes} bytes of DMA memory"));
        let pa = Platform::va_to_pa(x86_64::VirtAddr::new(va as u64)).as_u64();
        (va, pa)
    }

    /// The host stand-in, used only when this module is compiled by
    /// `dev_tests`.
    ///
    /// The one thing `Dma` needs from the platform is a page-aligned,
    /// physically contiguous block and the physical address of it, and the
    /// host has an allocator that can provide the first half. There is no
    /// second half: on the host nothing dereferences a physical address, so
    /// the virtual one stands in for it. That is enough for every property the
    /// tests are about -- what goes into a descriptor, and what comes back out
    /// of the used ring -- and it keeps the rings, the descriptor table and
    /// `read_into`/`fill` running against real memory rather than a model.
    ///
    /// The allocation is deliberately never freed. `Dma` has no `Drop` -- see
    /// `virtio::forget_posted_buffer`, which depends on that -- so a test that
    /// allocates one leaks it, exactly as the guest does.
    #[cfg(test)]
    fn allocate(_bytes: u64, order: u32) -> (*mut u8, u64) {
        let size = usize::try_from(u64::from(1_u32 << order) * 4096).expect("64-bit target");
        let layout = std::alloc::Layout::from_size_align(size, 4096).expect("valid layout");
        // SAFETY: `size` is non-zero -- `order` counts whole pages -- so this
        // is a well-formed request, and the result is checked for null.
        let va = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!va.is_null(), "out of memory allocating {size} test bytes");
        (va, va as u64)
    }

    /// Allocates at least `bytes` of DMA-capable memory.
    ///
    /// # Panics
    ///
    /// Panics if the allocation fails.
    pub fn alloc(bytes: u64) -> Self {
        Self::new(bytes)
    }

    /// The physical address the device must be given.
    pub fn pa(&self) -> u64 {
        self.pa
    }

    /// The usable capacity of the allocation, in bytes.
    ///
    /// This is the bound every device-supplied length is checked against, and
    /// the most a descriptor naming this buffer may ever be given.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Copies `bytes` into the start of the allocation.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is longer than the allocation's capacity. That length
    /// comes from this driver, not from the device, so exceeding it is a bug
    /// here rather than something a peer can provoke.
    pub fn fill(&mut self, bytes: &[u8]) {
        assert!(
            bytes.len() <= self.len,
            "{} bytes do not fit in a {}-byte DMA buffer",
            bytes.len(),
            self.len
        );
        // SAFETY: `self.va` is a live allocation of at least `self.len` bytes
        // (rounded up to whole pages), exclusively owned, and `bytes` is a
        // distinct borrow. The assert above bounds the copy by that length.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.va, bytes.len()) };
    }

    /// Reads the first `len` bytes back out into `out`.
    ///
    /// Used to see what a device wrote into a receive buffer.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the allocation's capacity, or if `out` is
    /// shorter than `len`.
    ///
    /// The first of those is a backstop, not the primary defence. `len`
    /// originates in `used_elem.len`, which the untrusted device writes, so it
    /// is clamped to the submitted capacity at the boundary where the
    /// completion is consumed -- see `Console::receive_deadline`. Checking it
    /// again here is what makes this safe `pub` function sound *on its own*,
    /// rather than sound only as long as every caller remembers to clamp.
    pub fn read_into(&self, out: &mut [u8], len: usize) {
        assert!(
            len <= self.len,
            "{len} bytes were requested from a {}-byte DMA buffer",
            self.len
        );
        assert!(out.len() >= len, "output slice is shorter than {len} bytes");
        // SAFETY: `len` is bounded by both the allocation's capacity and the
        // output slice's length by the asserts above, and the two regions are
        // distinct allocations.
        unsafe { core::ptr::copy_nonoverlapping(self.va, out.as_mut_ptr(), len) };
    }
}

/// What the driver believes about one descriptor table entry.
///
/// The free list alone cannot answer "is this descriptor outstanding?": it is
/// threaded through the `next` field of the entries that are *on* it, and
/// asking whether a given index is on a singly-linked list means walking it.
/// So the state is recorded alongside, one byte per descriptor, and every
/// transition is checked.
///
/// This exists because the device is untrusted -- in the two-VM arrangement it
/// is the normal world -- and a used-ring entry is a number it chooses. Without
/// the check, a device that reports the same `id` twice gets that descriptor
/// pushed onto the free list twice: the second push writes `next = free_head`
/// into the entry that *is* `free_head`, so the list becomes a one-element
/// cycle, and `num_free` is incremented past `size` until it wraps. From there
/// `submit` hands out the same descriptor to every caller for ever.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DescState {
    /// On the free list, available to [`Queue::submit`].
    Free,
    /// Handed to the device and not yet completed.
    InFlight,
    /// Handed to the device, and then given up on -- see [`Queue::abandon`].
    /// The device may still write the buffer it names, so that buffer is never
    /// reused; a late completion for it is legitimate and returns the
    /// descriptor (but not the buffer) to service.
    Abandoned,
}

/// A split virtqueue, sized and allocated but not yet registered with the
/// device.
pub struct Queue {
    /// The queue's index in the device, which is also what gets written to the
    /// notification address.
    index: u16,
    /// Number of descriptors. A power of two, as the specification requires,
    /// so the ring indices can be masked rather than divided.
    size: u16,

    desc: Dma,
    avail: Dma,
    used: Dma,

    /// Head of the free-descriptor list, threaded through `Desc::next`.
    free_head: u16,
    /// How many descriptors are free, so exhaustion is a clean error rather
    /// than a corrupted list.
    num_free: u16,
    /// The last `used.idx` this driver consumed. The device only ever
    /// increases `used.idx`, and it wraps at `u16`, so the difference between
    /// the two is the number of pending completions.
    last_used: u16,
    /// Per-descriptor state, `size` entries. See [`DescState`].
    states: Vec<DescState>,

    /// The device's own index into the notification region for this queue.
    notify_off: u16,
}

impl Queue {
    /// Allocates the three rings for a queue of `size` descriptors.
    ///
    /// # Panics
    ///
    /// Panics if `size` is zero or not a power of two. Both are the device's
    /// responsibility to get right, and a non-power-of-two size would make
    /// every masked ring index wrong.
    pub fn new(index: u16, size: u16) -> Self {
        assert!(
            size > 0 && size.is_power_of_two(),
            "queue {index}: size {size} is not a non-zero power of two"
        );
        let n = u64::from(size);

        // The three layouts the specification fixes. Each gets its own
        // allocation, which is page-aligned and so trivially satisfies the
        // 16-, 2- and 4-byte alignment requirements; packing them into one
        // allocation would save at most two pages and would make the
        // alignment argument something to be checked rather than obvious.
        let desc = Dma::new(16 * n);
        // flags, idx, ring[n], used_event.
        let avail = Dma::new(6 + 2 * n);
        // flags, idx, ring[n] of (id, len), avail_event.
        let used = Dma::new(6 + 8 * n);

        let mut queue = Self {
            index,
            size,
            desc,
            avail,
            used,
            free_head: 0,
            num_free: size,
            last_used: 0,
            states: vec![DescState::Free; size as usize],
            notify_off: 0,
        };

        // Thread every descriptor onto the free list. The last one's `next` is
        // left at zero, which is never followed: `num_free` reaches zero
        // first.
        for i in 0..size {
            queue.write_desc(
                i,
                Desc {
                    addr: 0,
                    len: 0,
                    flags: 0,
                    next: i.wrapping_add(1) % size,
                },
            );
        }

        queue
    }

    /// The queue's index in the device.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// The number of descriptors.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Physical address of the descriptor table.
    pub fn desc_pa(&self) -> u64 {
        self.desc.pa
    }

    /// Physical address of the available ring.
    pub fn driver_pa(&self) -> u64 {
        self.avail.pa
    }

    /// Physical address of the used ring.
    pub fn device_pa(&self) -> u64 {
        self.used.pa
    }

    /// Records the notification index the device reported for this queue.
    pub fn set_notify_off(&mut self, notify_off: u16) {
        self.notify_off = notify_off;
    }

    /// The notification index the device reported.
    pub fn notify_off(&self) -> u16 {
        self.notify_off
    }

    /// Writes one descriptor table entry.
    fn write_desc(&mut self, index: u16, desc: Desc) {
        debug_assert!(index < self.size);
        // SAFETY: `index` is inside the table, which was allocated with room
        // for `size` entries and is exclusively owned by this queue. The
        // device may read it concurrently, which is why the store is volatile:
        // it must actually happen, and must not be merged with others.
        unsafe {
            self.desc
                .va
                .cast::<Desc>()
                .add(index as usize)
                .write_volatile(desc);
        }
    }

    /// Reads `avail.idx`.
    fn avail_idx(&self) -> u16 {
        // SAFETY: `avail.idx` is the second u16 of the available ring, which
        // is allocated and owned by this queue.
        unsafe { self.avail.va.cast::<u16>().add(1).read_volatile() }
    }

    /// Writes `avail.idx`.
    fn set_avail_idx(&mut self, idx: u16) {
        // SAFETY: as `avail_idx`.
        unsafe { self.avail.va.cast::<u16>().add(1).write_volatile(idx) }
    }

    /// Writes `avail.ring[slot]`.
    fn set_avail_ring(&mut self, slot: u16, desc_index: u16) {
        // SAFETY: the ring starts at the third u16 of the available ring and
        // has `size` entries; `slot` is masked into range by the caller.
        unsafe {
            self.avail
                .va
                .cast::<u16>()
                .add(2 + slot as usize)
                .write_volatile(desc_index);
        }
    }

    /// Reads `used.idx`.
    fn used_idx(&self) -> u16 {
        // SAFETY: `used.idx` is the second u16 of the used ring.
        unsafe { self.used.va.cast::<u16>().add(1).read_volatile() }
    }

    /// Reads `used.ring[slot]`.
    fn used_elem(&self, slot: u16) -> UsedElem {
        // The ring starts four bytes in, past `flags` and `idx`.
        //
        // SAFETY: `slot` is masked into `0..size` by the caller, and the used
        // ring was allocated with room for `size` entries after that header.
        unsafe {
            self.used
                .va
                .add(4)
                .cast::<UsedElem>()
                .add(slot as usize)
                .read_volatile()
        }
    }

    /// Publishes a single-descriptor chain naming the buffer at physical
    /// address `pa`, and returns the descriptor index.
    ///
    /// `device_writable` picks the direction: a receive buffer is written by
    /// the device and must be marked so, a transmit buffer is read by it and
    /// must not.
    ///
    /// Returns `None` if no descriptor is free.
    ///
    /// # Safety
    ///
    /// The buffer at `pa` becomes shared with the device until the chain
    /// completes. The caller must keep it allocated, must not read a
    /// device-writable buffer before completion, and must not write a
    /// device-readable one.
    pub unsafe fn submit(&mut self, pa: u64, len: u32, device_writable: bool) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let head = self.free_head;
        // The free list and `states` are two descriptions of the same thing,
        // and this is where they are required to agree. They can only diverge
        // through a bug here or through a completion that got past
        // `take_used`'s check, and handing out a descriptor the device still
        // owns is the failure this whole mechanism exists to prevent.
        assert_eq!(
            self.states.get(head as usize).copied(),
            Some(DescState::Free),
            "queue {}: free list head {head} is not free",
            self.index
        );
        // SAFETY: the free list is threaded through `next` and `head` is on
        // it, so this read is of a live entry.
        let next_free = unsafe {
            self.desc
                .va
                .cast::<Desc>()
                .add(head as usize)
                .read_volatile()
                .next
        };

        self.write_desc(
            head,
            Desc {
                addr: pa,
                len,
                flags: if device_writable { DESC_F_WRITE } else { 0 },
                next: 0,
            },
        );
        self.free_head = next_free;
        self.num_free -= 1;
        self.states[head as usize] = DescState::InFlight;

        // Publish. The ring is `size` entries and `avail.idx` is a free-running
        // counter, so the slot is the counter masked -- the ring wraps but the
        // counter does not.
        let idx = self.avail_idx();
        self.set_avail_ring(idx % self.size, head);

        // The descriptor and the ring slot above must be visible to the device
        // before the index that makes them live. Without this the device is
        // entitled to see the new `idx` and the old ring slot.
        fence(Ordering::SeqCst);
        self.set_avail_idx(idx.wrapping_add(1));
        // And the index must be visible before the notification that tells the
        // device to go and look.
        fence(Ordering::SeqCst);

        Some(head)
    }

    /// Gives up on an outstanding descriptor.
    ///
    /// There is no way to withdraw a published descriptor. Virtio 1.0 without
    /// `VIRTIO_F_RING_RESET` -- which this driver does not negotiate -- has no
    /// per-queue reset, and the only reset that exists is of the whole device.
    /// So giving up on a descriptor means giving up on its *buffer*,
    /// permanently: the descriptor stays posted, and the device is entitled to
    /// write into that buffer at any point from now on. The caller must never
    /// touch, free or reuse it again.
    ///
    /// What this records is that fact, so that the late completion which may
    /// still arrive is recognised as legitimate rather than treated as a
    /// replayed id.
    ///
    /// # Panics
    ///
    /// Panics if `head` is not outstanding: abandoning something the queue does
    /// not hold means the caller has lost track of what it submitted.
    pub fn abandon(&mut self, head: u16) {
        assert_eq!(
            self.states.get(head as usize).copied(),
            Some(DescState::InFlight),
            "queue {}: descriptor {head} is not in flight and cannot be abandoned",
            self.index
        );
        self.states[head as usize] = DescState::Abandoned;
        log::error!(
            "virtio     queue {}: descriptor {head} abandoned while still posted; its buffer \
             belongs to the device from now on and is never reused",
            self.index
        );
    }

    /// Takes one completion off the used ring, if there is one.
    ///
    /// Returns the head descriptor index and the number of bytes the device
    /// wrote, and returns the descriptor to the free list.
    ///
    /// A completion for an abandoned descriptor returns the *descriptor* to the
    /// free list -- the device has finished with it, so it is safe to hand out
    /// again -- but is not reported as a completion, because nobody is waiting
    /// on it and its buffer stays given up.
    ///
    /// A completion naming a descriptor that is not outstanding is **not** a
    /// completion: it is the untrusted device replaying an `id`, and honouring
    /// it would self-link the free list and wrap `num_free`. Such an entry is
    /// consumed -- `last_used` still advances, or the ring would never drain --
    /// logged at error level, and otherwise ignored. The same goes for a
    /// completion naming an `id` outside the descriptor table, which is
    /// rejected before it can index `states`.
    ///
    /// Both rejections return `None`, which a caller cannot tell apart from an
    /// empty ring; the error log is the only signal.
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        let idx = self.used_idx();
        if idx == self.last_used {
            return None;
        }
        // Read `used.idx` before the entry it publishes. Reversing these lets
        // a stale entry be paired with a fresh index.
        fence(Ordering::SeqCst);

        let elem = self.used_elem(self.last_used % self.size);
        self.last_used = self.last_used.wrapping_add(1);

        // `id` is a descriptor index, so anything outside the table means the
        // device wrote nonsense -- or that the ring is being read at the wrong
        // offset. Either way, returning it would corrupt the free list.
        let Some(head) = u16::try_from(elem.id).ok().filter(|id| *id < self.size) else {
            log::error!(
                "virtio     queue {}: completion names descriptor {}, but the table has {} \
                 entries; ignored",
                self.index,
                elem.id,
                self.size
            );
            return None;
        };

        match self.states[head as usize] {
            DescState::InFlight => {}
            DescState::Abandoned => log::warn!(
                "virtio     queue {}: late completion for abandoned descriptor {head}; the \
                 descriptor is reclaimed, its buffer is not",
                self.index
            ),
            DescState::Free => {
                log::error!(
                    "virtio     queue {}: completion for descriptor {head}, which is not in \
                     flight; the device is replaying a used-ring id. Ignored -- honouring it \
                     would self-link the free list.",
                    self.index
                );
                return None;
            }
        }

        // Return the chain -- one descriptor, since nothing chains here -- to
        // the free list.
        self.write_desc(
            head,
            Desc {
                addr: 0,
                len: 0,
                flags: 0,
                next: self.free_head,
            },
        );
        self.free_head = head;
        self.num_free += 1;
        let was = core::mem::replace(&mut self.states[head as usize], DescState::Free);

        // An abandoned descriptor has no caller waiting on it, so reporting it
        // as a completion would make it look like the answer to whatever the
        // caller submitted most recently.
        (was == DescState::InFlight).then_some((head, elem.len))
    }
}

// ---------------------------------------------------------------------------
// Tests.
//
// The device is the untrusted party here, so these tests *are* the device:
// they write used-ring entries directly, which is the only thing a device can
// do to this driver and the only thing the checks in `submit` and `take_used`
// defend against. Nothing is modelled -- the real `Queue` runs against real
// rings in real memory, with `Dma::allocate`'s host stand-in underneath.
//
// `dev_tests/tests/kvm_virtio_queue.rs` compiles this file for the host; see
// the comment there.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{DESC_F_WRITE, Desc, DescState, Dma, Queue, UsedElem};
    use alloc::vec::Vec;

    /// A buffer to submit. Its contents are irrelevant; what matters is that
    /// the physical address in the descriptor is this one.
    fn buffer() -> Dma {
        Dma::alloc(64)
    }

    /// Everything the untrusted device can do to this driver: write a used
    /// ring entry and bump `used.idx`.
    ///
    /// Deliberately unconditional. `id` is not checked, not bounded and not
    /// required to name anything outstanding, because none of those is a
    /// property the device is obliged to have; the whole point of the checks
    /// under test is that the driver cannot assume otherwise.
    fn device_completes(queue: &mut Queue, id: u32, len: u32) {
        let idx = queue.used_idx();
        let slot = usize::from(idx % queue.size);
        // SAFETY: the used ring was allocated with room for `size` entries
        // after its four-byte header, and `slot` is masked into that range.
        // This is the device's half of the shared memory.
        unsafe {
            queue
                .used
                .va
                .add(4)
                .cast::<UsedElem>()
                .add(slot)
                .write_volatile(UsedElem { id, len });
            queue
                .used
                .va
                .cast::<u16>()
                .add(1)
                .write_volatile(idx.wrapping_add(1));
        }
    }

    /// One descriptor table entry, as the device would read it.
    fn read_desc(queue: &Queue, index: u16) -> Desc {
        // SAFETY: `index` is inside the table, which has room for `size`
        // entries.
        unsafe {
            queue
                .desc
                .va
                .cast::<Desc>()
                .add(usize::from(index))
                .read_volatile()
        }
    }

    /// Submits `buffer` device-writable and returns the descriptor.
    fn submit(queue: &mut Queue, buffer: &Dma) -> Option<u16> {
        // SAFETY: nothing in a host test reads or writes the buffer while it
        // is posted, which is the whole of the contract; there is no device.
        unsafe { queue.submit(buffer.pa(), 64, true) }
    }

    /// The invariant the replay bug destroyed, checked after every step:
    /// `num_free` counts descriptors, so it can never exceed the table, and it
    /// must agree with the number of entries recorded `Free`.
    fn check_invariants(queue: &Queue) {
        assert!(
            queue.num_free <= queue.size,
            "num_free is {} for a {}-descriptor queue",
            queue.num_free,
            queue.size
        );
        let free = queue
            .states
            .iter()
            .filter(|s| **s == DescState::Free)
            .count();
        assert_eq!(
            usize::from(queue.num_free),
            free,
            "num_free is {} but {free} descriptors are recorded free",
            queue.num_free
        );
    }

    /// Walks the free list from its head, and asserts that it is a list of
    /// `num_free` distinct entries rather than a cycle.
    ///
    /// This is the shape the bug produced: pushing an already-free descriptor
    /// writes `next = free_head` into the entry that *is* `free_head`, making
    /// a one-element loop that `submit` then walks for ever.
    fn check_free_list(queue: &Queue) {
        let mut seen = Vec::new();
        let mut cursor = queue.free_head;
        for _ in 0..queue.num_free {
            assert!(
                !seen.contains(&cursor),
                "the free list revisits descriptor {cursor} after {seen:?}"
            );
            assert_eq!(
                queue.states[usize::from(cursor)],
                DescState::Free,
                "the free list contains descriptor {cursor}, which is not free"
            );
            seen.push(cursor);
            cursor = read_desc(queue, cursor).next;
        }
    }

    #[test]
    fn a_submitted_descriptor_names_the_buffer() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");
        let desc = read_desc(&queue, head);
        assert_eq!(desc.addr, dma.pa());
        assert_eq!(desc.len, 64);
        assert_eq!(desc.flags, DESC_F_WRITE);
        assert_eq!(queue.num_free, 3);
        check_invariants(&queue);
    }

    /// The regression `e7b44d29` fixed.
    ///
    /// The device reports one completion twice. The second report used to
    /// push an already-free descriptor onto the free list, which writes
    /// `next = free_head` into the entry that *is* `free_head`: the list
    /// becomes a one-element cycle and `num_free` is incremented past the
    /// table size. From there `submit` hands the same descriptor to every
    /// caller for ever.
    #[test]
    fn a_replayed_used_id_is_refused() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");

        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(queue.take_used(), Some((head, 8)));
        assert_eq!(queue.num_free, 4);
        check_invariants(&queue);
        check_free_list(&queue);

        // The replay.
        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(
            queue.take_used(),
            None,
            "a completion for a descriptor that is not in flight was honoured"
        );
        assert_eq!(
            queue.num_free, 4,
            "the replay inflated the free count past the table size"
        );
        check_invariants(&queue);
        check_free_list(&queue);

        // And the queue still hands out every descriptor exactly once, which
        // is what the self-linked list made impossible.
        let buffers: Vec<Dma> = (0..4).map(|_| buffer()).collect();
        let mut handed = Vec::new();
        for dma in &buffers {
            let head = submit(&mut queue, dma).expect("four descriptors remain");
            assert!(
                !handed.contains(&head),
                "descriptor {head} handed out twice"
            );
            handed.push(head);
        }
        assert_eq!(handed.len(), 4);
        assert_eq!(submit(&mut queue, &dma), None, "the queue is exhausted");
        check_invariants(&queue);
    }

    /// A completion naming a descriptor that was never submitted. There is no
    /// replay involved: the device simply names a free entry.
    #[test]
    fn a_completion_for_a_free_descriptor_is_refused() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");

        // Every descriptor except the one in flight is free.
        for id in 0..4 {
            if id == u32::from(head) {
                continue;
            }
            device_completes(&mut queue, id, 8);
            assert_eq!(queue.take_used(), None, "descriptor {id} is free");
            assert_eq!(queue.num_free, 3);
            check_invariants(&queue);
            check_free_list(&queue);
        }
        // The real completion still works afterwards.
        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(queue.take_used(), Some((head, 8)));
        check_invariants(&queue);
    }

    /// An `id` outside the descriptor table is rejected before it can index
    /// `states`, and the entry is still consumed so the ring drains.
    #[test]
    fn an_out_of_range_used_id_is_refused_and_consumed() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");

        for id in [4, 5, 0xFFFF, u32::from(u16::MAX) + 1, u32::MAX] {
            let before = queue.last_used;
            device_completes(&mut queue, id, 8);
            assert_eq!(queue.take_used(), None, "id {id} is out of range");
            assert_eq!(
                queue.last_used,
                before.wrapping_add(1),
                "the rejected entry was not consumed, so the ring cannot drain"
            );
            assert_eq!(queue.num_free, 3);
            check_invariants(&queue);
            check_free_list(&queue);
        }

        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(queue.take_used(), Some((head, 8)));
        check_invariants(&queue);
    }

    /// Sustained churn with a device that lies at every opportunity.
    ///
    /// Each round submits what it can, completes some of it honestly, and then
    /// adds one hostile entry drawn from the four kinds the driver has to
    /// survive: a replay of an id just completed, an out-of-range id, a
    /// completion for a descriptor that is free, and a late completion for one
    /// that was abandoned. The invariants are checked after every single step,
    /// so the round in which one first breaks is the one reported.
    #[test]
    fn churn_against_a_lying_device_keeps_the_free_list_sound() {
        const SIZE: u16 = 8;
        let mut queue = Queue::new(0, SIZE);
        let buffers: Vec<Dma> = (0..SIZE).map(|_| buffer()).collect();
        // A deterministic stand-in for randomness: xorshift, so a failure is
        // reproducible without a seed to record.
        let mut rng = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };

        let mut in_flight: Vec<u16> = Vec::new();
        let mut abandoned: Vec<u16> = Vec::new();
        let mut last_completed: Option<u16> = None;

        for round in 0..200_u32 {
            // Submit as many as the round asks for and the queue allows.
            let wanted = usize::try_from(next() % u64::from(SIZE)).expect("small");
            for _ in 0..wanted {
                let Some(head) = submit(&mut queue, &buffers[in_flight.len() % buffers.len()])
                else {
                    break;
                };
                assert!(
                    !in_flight.contains(&head) && !abandoned.contains(&head),
                    "round {round}: descriptor {head} was handed out while still outstanding"
                );
                in_flight.push(head);
                check_invariants(&queue);
            }

            // Abandon one, occasionally.
            if !in_flight.is_empty() && next() % 5 == 0 {
                let victim = in_flight
                    .swap_remove(usize::try_from(next() % in_flight.len() as u64).expect("small"));
                queue.abandon(victim);
                abandoned.push(victim);
                check_invariants(&queue);
            }

            // Honest completions.
            if !in_flight.is_empty() {
                let done = in_flight
                    .swap_remove(usize::try_from(next() % in_flight.len() as u64).expect("small"));
                device_completes(&mut queue, u32::from(done), 8);
                assert_eq!(
                    queue.take_used(),
                    Some((done, 8)),
                    "round {round}: an honest completion for {done} was refused"
                );
                last_completed = Some(done);
                check_invariants(&queue);
                check_free_list(&queue);
            }

            // And one lie.
            match next() % 4 {
                0 => {
                    // Only when it really is free: a descriptor completed in
                    // an earlier round may since have been submitted again, or
                    // abandoned, and in either of those cases the "replay" is
                    // a legitimate completion rather than a lie.
                    if let Some(replay) =
                        last_completed.filter(|d| !in_flight.contains(d) && !abandoned.contains(d))
                    {
                        device_completes(&mut queue, u32::from(replay), 8);
                        assert_eq!(
                            queue.take_used(),
                            None,
                            "round {round}: a replayed id {replay} was honoured"
                        );
                    }
                }
                1 => {
                    let bogus = u32::from(SIZE) + (next() as u32 % 1000);
                    device_completes(&mut queue, bogus, 8);
                    assert_eq!(
                        queue.take_used(),
                        None,
                        "round {round}: an out-of-range id {bogus} was honoured"
                    );
                }
                2 => {
                    // Any descriptor that is neither in flight nor abandoned
                    // is free.
                    if let Some(free) =
                        (0..SIZE).find(|d| !in_flight.contains(d) && !abandoned.contains(d))
                    {
                        device_completes(&mut queue, u32::from(free), 8);
                        assert_eq!(
                            queue.take_used(),
                            None,
                            "round {round}: a completion for free descriptor {free} was honoured"
                        );
                    }
                }
                _ => {
                    // A late completion for something abandoned is
                    // *legitimate*: the descriptor comes back, but nobody is
                    // waiting on it, so it is not reported.
                    if !abandoned.is_empty() {
                        let late = abandoned.remove(0);
                        device_completes(&mut queue, u32::from(late), 8);
                        assert_eq!(
                            queue.take_used(),
                            None,
                            "round {round}: an abandoned descriptor {late} was reported as a \
                             completion nobody was waiting for"
                        );
                    }
                }
            }
            check_invariants(&queue);
            check_free_list(&queue);
        }

        // Nothing leaked: every descriptor is accounted for.
        assert_eq!(
            usize::from(queue.num_free) + in_flight.len() + abandoned.len(),
            usize::from(SIZE)
        );
    }

    // -----------------------------------------------------------------------
    // Giving up on an outstanding descriptor -- `172263bc`.
    //
    // The half of that fix which lives here is `abandon`: a descriptor given
    // up on is *still posted*, so it must not be reissued, its buffer must not
    // be reused, and the late completion that may still arrive must be
    // recognised as legitimate rather than as a replayed id. The other half --
    // taking the `Dma` out of the caller's `Option` and leaking it -- is
    // `virtio::forget_posted_buffer`, which is not hosted; see the report.
    // -----------------------------------------------------------------------

    /// The fact that makes giving up the buffer necessary: after `abandon` the
    /// descriptor still names the buffer and is still marked device-writable,
    /// so the device remains entitled to write into it at any later moment.
    /// Nothing withdraws it, because virtio 1.0 without `VIRTIO_F_RING_RESET`
    /// has nothing that could.
    #[test]
    fn an_abandoned_descriptor_is_still_posted_against_its_buffer() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");

        queue.abandon(head);

        let desc = read_desc(&queue, head);
        assert_eq!(
            desc.addr,
            dma.pa(),
            "the descriptor stopped naming the buffer"
        );
        assert_eq!(
            desc.flags & DESC_F_WRITE,
            DESC_F_WRITE,
            "the descriptor is no longer device-writable, which it must remain: nothing \
             withdrew it"
        );
        assert_eq!(
            queue.states[usize::from(head)],
            DescState::Abandoned,
            "the descriptor was not recorded as given up on"
        );
        check_invariants(&queue);
    }

    /// An abandoned descriptor is not free, so it is not reissued -- handing it
    /// out would point a second buffer at a descriptor the device may write
    /// through at any moment.
    ///
    /// This one does **not** discriminate the fix: before `172263bc` the
    /// descriptor stayed `InFlight`, which also keeps it off the free list, so
    /// it passes either way. It is here to state the property, not to pin the
    /// regression; the tests that pin it are the two either side of this one.
    #[test]
    fn an_abandoned_descriptor_is_not_reissued() {
        const SIZE: u16 = 4;
        let mut queue = Queue::new(0, SIZE);
        let buffers: Vec<Dma> = (0..SIZE).map(|_| buffer()).collect();

        let head = submit(&mut queue, &buffers[0]).expect("a fresh queue has descriptors");
        queue.abandon(head);
        assert_eq!(queue.num_free, SIZE - 1);

        // The remaining three, and then exhaustion. The abandoned one is never
        // among them.
        for dma in &buffers[1..] {
            let got = submit(&mut queue, dma).expect("three descriptors remain");
            assert_ne!(got, head, "the abandoned descriptor was handed out again");
        }
        assert_eq!(
            submit(&mut queue, &buffers[0]),
            None,
            "the queue handed out a fourth descriptor, which can only be the abandoned one"
        );
        check_invariants(&queue);
        check_free_list(&queue);
    }

    /// The late completion. The device has finished with the descriptor, so
    /// the *descriptor* comes back -- but nobody is waiting on it, so it must
    /// not be reported as a completion, or it would look like the answer to
    /// whatever was submitted most recently. Its buffer stays given up
    /// regardless; that is the caller's `None`.
    #[test]
    fn a_late_completion_for_an_abandoned_descriptor_reclaims_it_silently() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");
        queue.abandon(head);

        // Something else is submitted and completes in the meantime, exactly
        // as the next request would.
        let other_dma = buffer();
        let other = submit(&mut queue, &other_dma).expect("descriptors remain");
        assert_ne!(other, head);

        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(
            queue.take_used(),
            None,
            "the abandoned descriptor was reported as a completion, so the caller waiting \
             for {other} would have taken it for that answer"
        );
        assert_eq!(queue.num_free, 3, "the descriptor was not reclaimed");
        assert_eq!(queue.states[usize::from(head)], DescState::Free);
        check_invariants(&queue);
        check_free_list(&queue);

        // The real completion is unaffected.
        device_completes(&mut queue, u32::from(other), 12);
        assert_eq!(queue.take_used(), Some((other, 12)));
        check_invariants(&queue);
    }

    /// Once the late completion has been taken, the descriptor is free like
    /// any other -- so a *second* completion for it is a replay again, and is
    /// refused. Abandoning does not buy the device a permanent licence.
    #[test]
    fn a_second_completion_for_an_abandoned_descriptor_is_a_replay() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");
        queue.abandon(head);

        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(queue.take_used(), None);
        assert_eq!(queue.num_free, 4);

        device_completes(&mut queue, u32::from(head), 8);
        assert_eq!(queue.take_used(), None);
        assert_eq!(
            queue.num_free, 4,
            "the second completion inflated the free count"
        );
        check_invariants(&queue);
        check_free_list(&queue);
    }

    /// Abandoning something the queue does not hold means the caller has lost
    /// track of what it submitted, which is a bug here rather than anything a
    /// device can provoke.
    #[test]
    #[should_panic(expected = "is not in flight and cannot be abandoned")]
    fn abandoning_a_free_descriptor_panics() {
        let mut queue = Queue::new(0, 4);
        queue.abandon(0);
    }

    #[test]
    #[should_panic(expected = "is not in flight and cannot be abandoned")]
    fn abandoning_the_same_descriptor_twice_panics() {
        let mut queue = Queue::new(0, 4);
        let dma = buffer();
        let head = submit(&mut queue, &dma).expect("a fresh queue has descriptors");
        queue.abandon(head);
        queue.abandon(head);
    }

    #[test]
    #[should_panic(expected = "is not in flight and cannot be abandoned")]
    fn abandoning_a_descriptor_outside_the_table_panics() {
        let mut queue = Queue::new(0, 4);
        queue.abandon(9);
    }
}
