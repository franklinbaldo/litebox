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

use litebox_platform_lvbs::mm::MemoryProvider as _;
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
    /// The buddy allocator hands out whole `1 << order` page blocks that are
    /// contiguous in both address spaces, which is exactly the property a
    /// virtqueue needs and the reason nothing smaller-grained is used here.
    ///
    /// # Panics
    ///
    /// Panics if the allocation fails.
    fn new(bytes: u64) -> Self {
        let pages = bytes.div_ceil(4096).max(1);
        let order = pages.next_power_of_two().trailing_zeros();
        let va = Platform::mem_allocate_pages(order)
            .unwrap_or_else(|| panic!("out of memory allocating {bytes} bytes of DMA memory"));
        let size = usize::try_from(u64::from(1_u32 << order) * 4096).expect("64-bit target");
        // The device reads this memory before the driver writes every byte of
        // it -- `avail.flags`, the used ring's contents and the tail of the
        // descriptor table are all read while still untouched. Zeroing means
        // it reads defined values rather than whatever the heap last held.
        //
        // SAFETY: `mem_allocate_pages` returned a live, exclusively owned
        // allocation of exactly this size.
        unsafe { core::ptr::write_bytes(va, 0, size) };
        // The typed ring accesses elsewhere in this module cast this pointer
        // to `Desc`, `UsedElem` and `u16`. They are sound because the
        // allocator returns whole pages; assert it rather than believe it.
        assert!(
            (va as usize).is_multiple_of(4096),
            "DMA allocation {va:p} is not page-aligned"
        );
        Self {
            pa: Platform::va_to_pa(x86_64::VirtAddr::new(va as u64)).as_u64(),
            va,
            len: usize::try_from(bytes).expect("64-bit target"),
        }
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
