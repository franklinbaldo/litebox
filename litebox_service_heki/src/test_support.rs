// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    vec::Vec,
};

use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{
    FrameTxn, HEKI_MAX_RANGES, HekiPage, HekiRange, MemAttr, PAGE_SIZE, ReservationStatus,
    VsmError, Vtl0Gate,
};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};

#[derive(Clone, Default)]
pub(super) struct MockVtl0Gate {
    state: Arc<Mutex<MockVtl0State>>,
}

#[derive(Default)]
struct MockVtl0State {
    pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    next_sparse_pa: u64,
    owned_ranges: BTreeSet<(u64, u64)>,
    protections: BTreeMap<(u64, u64), MemAttr>,
    protection_operations: Vec<(u64, u64, MemAttr)>,
    ringbuffer: Option<(u64, u64)>,
    end_of_boot_reached: bool,
    lock_count: usize,
}

impl MockVtl0Gate {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn insert_page(&self, address: u64, page: &[u8; PAGE_SIZE]) {
        assert_eq!(
            address % PAGE_SIZE as u64,
            0,
            "page address must be aligned"
        );
        self.state.lock().unwrap().pages.insert(address, *page);
    }

    pub(super) fn write_phys_span(&self, mut address: u64, mut bytes: &[u8]) {
        let mut state = self.state.lock().unwrap();
        while !bytes.is_empty() {
            let page_address = address & !(PAGE_SIZE as u64 - 1);
            let offset =
                usize::try_from(address - page_address).expect("page offset always fits in usize");
            let count = bytes.len().min(PAGE_SIZE - offset);
            let page = state
                .pages
                .get_mut(&page_address)
                .expect("physical page must be inserted before writing");
            page[offset..offset + count].copy_from_slice(&bytes[..count]);
            address += u64::try_from(count).expect("copy length always fits in u64");
            bytes = &bytes[count..];
        }
    }

    pub(super) fn write_heki_ranges(&self, ranges: &[HekiRange]) -> (u64, u64) {
        assert!(
            !ranges.is_empty(),
            "HEKI range chains must contain at least one range"
        );

        let page_count = ranges.len().div_ceil(HEKI_MAX_RANGES);
        let mut state = self.state.lock().unwrap();
        let mut page_addresses = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            let mut address = if state.next_sparse_pa == 0 {
                0x1000_0000
            } else {
                state.next_sparse_pa
            };
            while state.pages.contains_key(&address) {
                address += 0x11_000;
            }
            state.next_sparse_pa = address + 0x11_000;
            page_addresses.push(address);
        }

        for (index, chunk) in ranges.chunks(HEKI_MAX_RANGES).enumerate() {
            let mut page = HekiPage::new();
            page.nranges = chunk.len() as u64;
            page.ranges[..chunk.len()].copy_from_slice(chunk);
            if let Some(&next_address) = page_addresses.get(index + 1) {
                // This mock models the kernel's virtual link with an identity VA/PA mapping.
                page.next = next_address;
                page.next_pa = next_address;
            }
            // HekiPage is exactly one fully initialized 4 KiB page.
            let bytes = unsafe { core::mem::transmute::<HekiPage, [u8; PAGE_SIZE]>(page) };
            state.pages.insert(page_addresses[index], bytes);
        }

        (page_addresses[0], ranges.len() as u64)
    }

    pub(super) fn overwrite_heki_page(&self, address: u64, page: &HekiPage) {
        assert_eq!(
            address % PAGE_SIZE as u64,
            0,
            "page address must be aligned"
        );
        // HekiPage is exactly one fully initialized 4 KiB page.
        let bytes = unsafe { core::mem::transmute::<HekiPage, [u8; PAGE_SIZE]>(*page) };
        self.state.lock().unwrap().pages.insert(address, bytes);
    }

    pub(super) fn owned_ranges(&self) -> Vec<(u64, u64)> {
        self.state
            .lock()
            .unwrap()
            .owned_ranges
            .iter()
            .copied()
            .collect()
    }

    pub(super) fn protections(&self) -> Vec<(u64, u64, MemAttr)> {
        self.state
            .lock()
            .unwrap()
            .protections
            .iter()
            .map(|(&(start, end), &attr)| (start, end, attr))
            .collect()
    }

    pub(super) fn protection_operations(&self) -> Vec<(u64, u64, MemAttr)> {
        self.state.lock().unwrap().protection_operations.clone()
    }

    pub(super) fn ringbuffer(&self) -> Option<(u64, u64)> {
        self.state.lock().unwrap().ringbuffer
    }

    pub(super) fn set_end_of_boot_reached(&self) {
        self.state.lock().unwrap().end_of_boot_reached = true;
    }

    pub(super) fn control_registers_locked(&self) -> bool {
        self.lock_count() > 0
    }

    pub(super) fn lock_count(&self) -> usize {
        self.state.lock().unwrap().lock_count
    }
}

struct MockFrameTxn {
    state: Arc<Mutex<MockVtl0State>>,
    owned_ranges: BTreeSet<(u64, u64)>,
    new_ranges: Vec<(u64, u64)>,
    protection_updates: BTreeMap<(u64, u64), MemAttr>,
}

fn normalized_range(range: PhysFrameRange<Size4KiB>) -> (u64, u64) {
    (
        range.start.start_address().as_u64(),
        range.end.start_address().as_u64(),
    )
}

fn ranges_cover(ranges: &BTreeSet<(u64, u64)>, requested: (u64, u64)) -> bool {
    let mut covered_until = requested.0;
    for &(start, end) in ranges {
        if end <= covered_until {
            continue;
        }
        if start > covered_until {
            return false;
        }
        covered_until = end;
        if covered_until >= requested.1 {
            return true;
        }
    }
    requested.0 >= requested.1
}

fn ranges_overlap(ranges: &BTreeSet<(u64, u64)>, requested: (u64, u64)) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| requested.0 < end && start < requested.1)
}

fn insert_range(ranges: &mut BTreeSet<(u64, u64)>, mut inserted: (u64, u64)) {
    let merged: Vec<_> = ranges
        .iter()
        .copied()
        .filter(|&(start, end)| inserted.0 <= end && start <= inserted.1)
        .collect();
    for range in merged {
        ranges.remove(&range);
        inserted.0 = inserted.0.min(range.0);
        inserted.1 = inserted.1.max(range.1);
    }
    if inserted.0 < inserted.1 {
        ranges.insert(inserted);
    }
}

fn subtract_ranges(ranges: &mut BTreeSet<(u64, u64)>, removed: (u64, u64)) {
    let overlapping: Vec<_> = ranges
        .iter()
        .copied()
        .filter(|&(start, end)| removed.0 < end && start < removed.1)
        .collect();
    for (start, end) in overlapping {
        ranges.remove(&(start, end));
        insert_range(ranges, (start, removed.0.min(end)));
        insert_range(ranges, (removed.1.max(start), end));
    }
}

fn apply_protection(
    protections: &mut BTreeMap<(u64, u64), MemAttr>,
    range: (u64, u64),
    attr: MemAttr,
) {
    subtract_protections(protections, range);
    protections.insert(range, attr);
}

fn subtract_protections(protections: &mut BTreeMap<(u64, u64), MemAttr>, removed: (u64, u64)) {
    let overlapping: Vec<_> = protections
        .iter()
        .filter(|&(&(start, end), _)| removed.0 < end && start < removed.1)
        .map(|(&range, &attr)| (range, attr))
        .collect();
    for ((start, end), attr) in overlapping {
        protections.remove(&(start, end));
        if start < removed.0 {
            protections.insert((start, removed.0.min(end)), attr);
        }
        if removed.1 < end {
            protections.insert((removed.1.max(start), end), attr);
        }
    }
}

impl FrameTxn for MockFrameTxn {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let owned_before = self.owned_ranges.clone();
        let new_ranges_before = self.new_ranges.len();
        let mut seen = BTreeSet::new();
        let mut statuses = Vec::with_capacity(ranges.len());
        for range in ranges {
            let requested = normalized_range(*range);
            let globally_owned = self.state.lock().unwrap().owned_ranges.clone();
            let status = if requested.0 >= requested.1 {
                Ok(ReservationStatus::AlreadyOwned)
            } else if ranges_overlap(&seen, requested) {
                Err(VsmError::ProtectedFrameOverlap)
            } else if ranges_cover(&owned_before, requested) {
                Ok(ReservationStatus::AlreadyOwned)
            } else if ranges_overlap(&owned_before, requested)
                || ranges_overlap(&globally_owned, requested)
            {
                Err(VsmError::ProtectedFrameOverlap)
            } else {
                Ok(ReservationStatus::New)
            };
            let status = match status {
                Ok(status) => status,
                Err(error) => {
                    self.owned_ranges = owned_before;
                    self.new_ranges.truncate(new_ranges_before);
                    return Err(error);
                }
            };
            insert_range(&mut seen, requested);
            if status == ReservationStatus::New {
                insert_range(&mut self.owned_ranges, requested);
                self.new_ranges.push(requested);
            }
            statuses.push(status);
        }
        Ok(statuses)
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        let range = normalized_range(range);
        if !ranges_cover(&self.owned_ranges, range) {
            return Err(VsmError::ProtectedFrameOverlap);
        }
        apply_protection(&mut self.protection_updates, range, attr);
        Ok(())
    }
}

impl Vtl0Gate for MockVtl0Gate {
    fn read_vtl0_bytes(
        &self,
        pages: &[PhysPageAddr<PAGE_SIZE>],
        offset: usize,
        mut out: &mut [u8],
    ) -> Result<(), VsmError> {
        if offset >= PAGE_SIZE {
            return Err(VsmError::Vtl0CopyFailed);
        }

        let state = self.state.lock().unwrap();
        for (index, page_address) in pages.iter().enumerate() {
            if out.is_empty() {
                return Ok(());
            }
            let page = state
                .pages
                .get(&(page_address.as_usize() as u64))
                .ok_or(VsmError::Vtl0CopyFailed)?;
            let start = if index == 0 { offset } else { 0 };
            let count = out.len().min(PAGE_SIZE - start);
            out[..count].copy_from_slice(&page[start..start + count]);
            out = &mut out[count..];
        }

        if out.is_empty() {
            Ok(())
        } else {
            Err(VsmError::Vtl0CopyFailed)
        }
    }

    fn protect_frame(
        &self,
        range: PhysFrameRange<Size4KiB>,
        attr: MemAttr,
    ) -> Result<(), VsmError> {
        let mut state = self.state.lock().unwrap();
        let range = normalized_range(range);
        if attr.contains(MemAttr::MEM_ATTR_WRITE) {
            subtract_ranges(&mut state.owned_ranges, range);
        } else {
            insert_range(&mut state.owned_ranges, range);
        }
        apply_protection(&mut state.protections, range, attr);
        state.protection_operations.push((range.0, range.1, attr));
        Ok(())
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        let mut state = self.state.lock().unwrap();
        let range = normalized_range(range);
        subtract_ranges(&mut state.owned_ranges, range);
        subtract_protections(&mut state.protections, range);
        Ok(())
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut txn = MockFrameTxn {
            state: Arc::clone(&self.state),
            owned_ranges: BTreeSet::new(),
            new_ranges: Vec::new(),
            protection_updates: BTreeMap::new(),
        };
        txn.reserve(initial)?;
        f(&mut txn)?;

        let mut state = self.state.lock().unwrap();
        if txn
            .new_ranges
            .iter()
            .any(|&range| ranges_overlap(&state.owned_ranges, range))
        {
            return Err(VsmError::ProtectedFrameOverlap);
        }
        let mut committed_ownership = state.owned_ranges.clone();
        for &range in &txn.new_ranges {
            insert_range(&mut committed_ownership, range);
        }
        if txn
            .protection_updates
            .keys()
            .any(|&range| !ranges_cover(&committed_ownership, range))
        {
            return Err(VsmError::ProtectedFrameOverlap);
        }
        state.owned_ranges = committed_ownership;
        for (range, attr) in txn.protection_updates {
            apply_protection(&mut state.protections, range, attr);
            if attr.contains(MemAttr::MEM_ATTR_WRITE) {
                subtract_ranges(&mut state.owned_ranges, range);
            } else {
                insert_range(&mut state.owned_ranges, range);
            }
        }
        Ok(())
    }

    fn install_ringbuffer(&self, pa: u64, size: u64) {
        self.state.lock().unwrap().ringbuffer = Some((pa, size));
    }

    fn end_of_boot_reached(&self) -> bool {
        self.state.lock().unwrap().end_of_boot_reached
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        self.state.lock().unwrap().lock_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MockVtl0Gate;
    use alloc::{vec, vec::Vec};
    use litebox_common_linux::vmap::PhysPageAddr;
    use litebox_common_lvbs::{
        HEKI_MAX_RANGES, HekiPage, HekiRange, MemAttr, PAGE_SIZE, ReservationStatus, VsmError,
        Vtl0Gate,
    };
    use x86_64::{
        PhysAddr,
        structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange},
    };

    fn frame_range(start: u64, end: u64) -> PhysFrameRange<Size4KiB> {
        PhysFrameRange {
            start: PhysFrame::from_start_address(PhysAddr::new(start)).unwrap(),
            end: PhysFrame::from_start_address(PhysAddr::new(end)).unwrap(),
        }
    }

    #[test]
    fn reads_bytes_across_physical_pages() {
        let gate = MockVtl0Gate::new();
        gate.insert_page(0x1000, &[0; PAGE_SIZE]);
        gate.insert_page(0x9000, &[0; PAGE_SIZE]);
        gate.write_phys_span(0x1ffd, &[1, 2, 3]);
        gate.write_phys_span(0x9000, &[4, 5, 6]);

        let pages = [
            PhysPageAddr::<PAGE_SIZE>::new(0x1000).unwrap(),
            PhysPageAddr::<PAGE_SIZE>::new(0x9000).unwrap(),
        ];
        let mut out = [0; 6];
        gate.read_vtl0_bytes(&pages, PAGE_SIZE - 3, &mut out)
            .unwrap();
        assert_eq!(out, [1, 2, 3, 4, 5, 6]);

        let missing = [PhysPageAddr::<PAGE_SIZE>::new(0xa000).unwrap()];
        assert!(matches!(
            gate.read_vtl0_bytes(&missing, 0, &mut [0]),
            Err(VsmError::Vtl0CopyFailed)
        ));
    }

    #[test]
    fn builds_kernel_shaped_heki_page_chain() {
        let gate = MockVtl0Gate::new();
        let ranges: Vec<_> = (0..=HEKI_MAX_RANGES)
            .map(|index| HekiRange {
                va: 0xffff_8000_0000_0000 + index as u64 * PAGE_SIZE as u64,
                pa: 0x20_0000 + index as u64 * PAGE_SIZE as u64,
                epa: 0x20_1000 + index as u64 * PAGE_SIZE as u64,
                attributes: MemAttr::MEM_ATTR_READ.bits(),
            })
            .collect();

        let (first_pa, total_count) = gate.write_heki_ranges(&ranges);
        let first = gate.read_vtl0_val::<HekiPage>(first_pa).unwrap();
        let second = gate.read_vtl0_val::<HekiPage>(first.next_pa).unwrap();
        let first_nranges = first.nranges;
        let first_next = first.next;
        let first_next_pa = first.next_pa;
        let second_nranges = second.nranges;
        let second_next = second.next;
        let second_next_pa = second.next_pa;

        assert_eq!(first_nranges, HEKI_MAX_RANGES as u64);
        assert_eq!(second_nranges, 1);
        assert_ne!(first_pa, 0);
        assert_eq!(first_pa % PAGE_SIZE as u64, 0);
        assert_ne!(first_pa, first_next_pa);
        assert_eq!(first_next_pa % PAGE_SIZE as u64, 0);
        // The mock uses an identity VA/PA mapping for kernel-compatible links.
        assert_eq!(first_next, first_next_pa);
        assert_eq!(second_next, 0);
        assert_eq!(second_next_pa, 0);
        assert_eq!(total_count, ranges.len() as u64);
    }

    #[test]
    #[should_panic(expected = "HEKI range chains must contain at least one range")]
    fn rejects_empty_heki_page_chain() {
        MockVtl0Gate::new().write_heki_ranges(&[]);
    }

    #[test]
    fn transactional_closure_runs_and_propagates_errors() {
        let gate = MockVtl0Gate::new();
        let mut called = false;
        let result = gate.protect_frames_transactionally(&[], &mut |txn| {
            called = true;
            assert!(txn.reserve(&[]).unwrap().is_empty());
            Err(VsmError::BufferTooSmall("transaction test"))
        });

        assert!(called);
        assert!(matches!(
            result,
            Err(VsmError::BufferTooSmall("transaction test"))
        ));
    }

    #[test]
    fn successful_transaction_records_initial_ownership_and_final_protections() {
        let gate = MockVtl0Gate::new();
        let initial = frame_range(0x10000, 0x12000);
        let additional = frame_range(0x14000, 0x15000);

        gate.protect_frames_transactionally(&[initial], &mut |txn| {
            assert_eq!(txn.reserve(&[additional])?, vec![ReservationStatus::New]);
            txn.protect(initial, MemAttr::MEM_ATTR_READ)?;
            txn.protect(additional, MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_EXEC)
        })
        .unwrap();

        assert_eq!(
            gate.owned_ranges(),
            vec![(0x10000, 0x12000), (0x14000, 0x15000)]
        );
        assert_eq!(
            gate.protections(),
            vec![
                (0x10000, 0x12000, MemAttr::MEM_ATTR_READ),
                (
                    0x14000,
                    0x15000,
                    MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_EXEC
                ),
            ]
        );
    }

    #[test]
    fn failed_transaction_rolls_back_all_ownership_and_protection_changes() {
        let gate = MockVtl0Gate::new();
        let initial = frame_range(0x10000, 0x11000);
        let additional = frame_range(0x12000, 0x13000);

        let result = gate.protect_frames_transactionally(&[initial], &mut |txn| {
            txn.reserve(&[additional])?;
            txn.protect(initial, MemAttr::MEM_ATTR_READ)?;
            txn.protect(additional, MemAttr::MEM_ATTR_EXEC)?;
            Err(VsmError::BufferTooSmall("rollback"))
        });

        assert!(matches!(result, Err(VsmError::BufferTooSmall("rollback"))));
        assert!(gate.owned_ranges().is_empty());
        assert!(gate.protections().is_empty());
    }

    #[test]
    fn overlapping_initial_range_against_owned_frames_is_rejected() {
        let gate = MockVtl0Gate::new();
        gate.protect_frames_transactionally(&[frame_range(0x10000, 0x12000)], &mut |_| Ok(()))
            .unwrap();

        let mut closure_called = false;
        let result =
            gate.protect_frames_transactionally(&[frame_range(0x11000, 0x13000)], &mut |_| {
                closure_called = true;
                Ok(())
            });

        assert!(matches!(result, Err(VsmError::ProtectedFrameOverlap)));
        assert!(!closure_called);
        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x12000)]);
    }

    #[test]
    fn transaction_reserve_reports_repeated_transaction_ownership_consistently() {
        let gate = MockVtl0Gate::new();
        let fresh = frame_range(0x12000, 0x13000);

        gate.protect_frames_transactionally(&[], &mut |txn| {
            assert_eq!(txn.reserve(&[fresh])?, vec![ReservationStatus::New]);
            assert_eq!(
                txn.reserve(&[fresh])?,
                vec![ReservationStatus::AlreadyOwned]
            );
            Ok(())
        })
        .unwrap();

        assert_eq!(gate.owned_ranges(), vec![(0x12000, 0x13000)]);
    }

    #[test]
    fn transaction_reserve_reports_transaction_owned_subrange_as_already_owned() {
        let gate = MockVtl0Gate::new();

        gate.protect_frames_transactionally(&[frame_range(0x10000, 0x14000)], &mut |txn| {
            assert_eq!(
                txn.reserve(&[frame_range(0x11000, 0x13000)])?,
                vec![ReservationStatus::AlreadyOwned]
            );
            txn.protect(frame_range(0x11000, 0x13000), MemAttr::MEM_ATTR_READ)
        })
        .unwrap();

        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x14000)]);
        assert_eq!(
            gate.protections(),
            vec![(0x11000, 0x13000, MemAttr::MEM_ATTR_READ)]
        );
    }

    #[test]
    fn transaction_reserve_rejects_frames_owned_by_another_transaction() {
        let gate = MockVtl0Gate::new();
        let existing = frame_range(0x10000, 0x11000);
        gate.protect_frames_transactionally(&[existing], &mut |_| Ok(()))
            .unwrap();

        let result = gate
            .protect_frames_transactionally(&[], &mut |txn| txn.reserve(&[existing]).map(|_| ()));

        assert!(matches!(result, Err(VsmError::ProtectedFrameOverlap)));
        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x11000)]);
    }

    #[test]
    fn transaction_reserve_rejects_duplicate_or_overlapping_ranges_in_one_batch() {
        for ranges in [
            [frame_range(0x10000, 0x12000), frame_range(0x10000, 0x12000)],
            [frame_range(0x10000, 0x12000), frame_range(0x11000, 0x13000)],
        ] {
            let gate = MockVtl0Gate::new();
            let result = gate.protect_frames_transactionally(&[], &mut |txn| {
                assert!(matches!(
                    txn.reserve(&ranges),
                    Err(VsmError::ProtectedFrameOverlap)
                ));
                Ok(())
            });

            assert!(result.is_ok());
            assert!(gate.owned_ranges().is_empty());
        }
    }

    #[test]
    fn transaction_protect_rejects_an_unreserved_range() {
        let gate = MockVtl0Gate::new();
        let result = gate.protect_frames_transactionally(&[], &mut |txn| {
            txn.protect(frame_range(0x10000, 0x11000), MemAttr::MEM_ATTR_READ)
        });

        assert!(matches!(result, Err(VsmError::ProtectedFrameOverlap)));
        assert!(gate.protections().is_empty());
    }

    #[test]
    fn direct_protection_operations_are_observable() {
        let gate = MockVtl0Gate::new();
        let range = frame_range(0x10000, 0x12000);

        gate.protect_frame(range, MemAttr::MEM_ATTR_READ).unwrap();
        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x12000)]);
        assert_eq!(
            gate.protections(),
            vec![(0x10000, 0x12000, MemAttr::MEM_ATTR_READ)]
        );

        gate.unprotect_frames(range).unwrap();
        assert!(gate.owned_ranges().is_empty());
        assert!(gate.protections().is_empty());
    }

    #[test]
    fn direct_writable_protection_removes_registry_ownership() {
        let gate = MockVtl0Gate::new();
        let range = frame_range(0x10000, 0x12000);
        gate.protect_frame(range, MemAttr::MEM_ATTR_READ).unwrap();

        let writable = MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE;
        gate.protect_frame(range, writable).unwrap();

        assert!(gate.owned_ranges().is_empty());
        assert_eq!(gate.protections(), vec![(0x10000, 0x12000, writable)]);
        assert_eq!(
            gate.protection_operations(),
            vec![
                (0x10000, 0x12000, MemAttr::MEM_ATTR_READ),
                (0x10000, 0x12000, writable),
            ]
        );
    }

    #[test]
    fn transactional_writable_protection_removes_reserved_ownership() {
        let gate = MockVtl0Gate::new();
        let range = frame_range(0x10000, 0x12000);
        let writable = MemAttr::MEM_ATTR_READ | MemAttr::MEM_ATTR_WRITE;

        gate.protect_frames_transactionally(&[range], &mut |txn| txn.protect(range, writable))
            .unwrap();

        assert!(gate.owned_ranges().is_empty());
        assert_eq!(gate.protections(), vec![(0x10000, 0x12000, writable)]);
    }

    #[test]
    fn transactional_reservation_without_protection_remains_owned() {
        let gate = MockVtl0Gate::new();

        gate.protect_frames_transactionally(&[frame_range(0x10000, 0x12000)], &mut |_| Ok(()))
            .unwrap();

        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x12000)]);
    }

    #[test]
    fn unprotect_subrange_splits_owned_and_protected_ranges() {
        let gate = MockVtl0Gate::new();
        gate.protect_frame(frame_range(0x10000, 0x15000), MemAttr::MEM_ATTR_READ)
            .unwrap();

        gate.unprotect_frames(frame_range(0x12000, 0x13000))
            .unwrap();

        assert_eq!(
            gate.owned_ranges(),
            vec![(0x10000, 0x12000), (0x13000, 0x15000)]
        );
        assert_eq!(
            gate.protections(),
            vec![
                (0x10000, 0x12000, MemAttr::MEM_ATTR_READ),
                (0x13000, 0x15000, MemAttr::MEM_ATTR_READ),
            ]
        );
    }

    #[test]
    fn unprotect_spanning_range_subtracts_from_every_entry() {
        let gate = MockVtl0Gate::new();
        gate.protect_frame(frame_range(0x10000, 0x12000), MemAttr::MEM_ATTR_READ)
            .unwrap();
        gate.protect_frame(frame_range(0x13000, 0x16000), MemAttr::MEM_ATTR_EXEC)
            .unwrap();

        gate.unprotect_frames(frame_range(0x11000, 0x15000))
            .unwrap();

        assert_eq!(
            gate.owned_ranges(),
            vec![(0x10000, 0x11000), (0x15000, 0x16000)]
        );
        assert_eq!(
            gate.protections(),
            vec![
                (0x10000, 0x11000, MemAttr::MEM_ATTR_READ),
                (0x15000, 0x16000, MemAttr::MEM_ATTR_EXEC),
            ]
        );
    }

    #[test]
    fn transaction_commit_merges_unrelated_direct_mutation() {
        let gate = MockVtl0Gate::new();
        let concurrent_gate = gate.clone();

        gate.protect_frames_transactionally(&[frame_range(0x10000, 0x11000)], &mut |txn| {
            txn.protect(frame_range(0x10000, 0x11000), MemAttr::MEM_ATTR_READ)?;
            concurrent_gate.protect_frame(frame_range(0x14000, 0x15000), MemAttr::MEM_ATTR_EXEC)
        })
        .unwrap();

        assert_eq!(
            gate.owned_ranges(),
            vec![(0x10000, 0x11000), (0x14000, 0x15000)]
        );
        assert_eq!(
            gate.protections(),
            vec![
                (0x10000, 0x11000, MemAttr::MEM_ATTR_READ),
                (0x14000, 0x15000, MemAttr::MEM_ATTR_EXEC),
            ]
        );
    }

    #[test]
    fn transaction_commit_accepts_protection_covered_by_adjacent_new_ranges() {
        let gate = MockVtl0Gate::new();

        gate.protect_frames_transactionally(&[], &mut |txn| {
            assert_eq!(
                txn.reserve(&[frame_range(0x10000, 0x12000), frame_range(0x12000, 0x14000),])?,
                vec![ReservationStatus::New, ReservationStatus::New]
            );
            txn.protect(frame_range(0x10000, 0x14000), MemAttr::MEM_ATTR_READ)
        })
        .unwrap();

        assert_eq!(gate.owned_ranges(), vec![(0x10000, 0x14000)]);
        assert_eq!(
            gate.protections(),
            vec![(0x10000, 0x14000, MemAttr::MEM_ATTR_READ)]
        );
    }

    #[test]
    fn transaction_commit_rejects_new_conflict_without_partial_merge() {
        let gate = MockVtl0Gate::new();
        let concurrent_gate = gate.clone();

        let result =
            gate.protect_frames_transactionally(&[frame_range(0x10000, 0x12000)], &mut |txn| {
                txn.protect(frame_range(0x10000, 0x12000), MemAttr::MEM_ATTR_READ)?;
                concurrent_gate.protect_frame(frame_range(0x11000, 0x13000), MemAttr::MEM_ATTR_EXEC)
            });

        assert!(matches!(result, Err(VsmError::ProtectedFrameOverlap)));
        assert_eq!(gate.owned_ranges(), vec![(0x11000, 0x13000)]);
        assert_eq!(
            gate.protections(),
            vec![(0x11000, 0x13000, MemAttr::MEM_ATTR_EXEC)]
        );
    }

    #[test]
    fn platform_operations_update_observable_state() {
        let gate = MockVtl0Gate::new();

        assert!(!gate.end_of_boot_reached());
        assert!(!gate.control_registers_locked());
        assert_eq!(gate.ringbuffer(), None);

        gate.set_end_of_boot_reached();
        gate.lock_control_registers().unwrap();
        gate.install_ringbuffer(0x10000, 0x4000);

        assert!(gate.end_of_boot_reached());
        assert!(gate.control_registers_locked());
        assert_eq!(gate.ringbuffer(), Some((0x10000, 0x4000)));
    }
}
