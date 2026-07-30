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
use zerocopy::IntoBytes;

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
}

impl MockVtl0Gate {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn insert_kernel_page(&self, address: u64) {
        assert_eq!(address % PAGE_SIZE as u64, 0, "page must be aligned");
        self.state
            .lock()
            .unwrap()
            .pages
            .insert(address, [0; PAGE_SIZE]);
    }

    pub(super) fn write_split_kernel_span(
        &self,
        first_address: u64,
        second_page_address: u64,
        bytes: &[u8],
    ) {
        let first_page_address = first_address & !(PAGE_SIZE as u64 - 1);
        let first_offset = usize::try_from(first_address - first_page_address).unwrap();
        let first_count = bytes.len().min(PAGE_SIZE - first_offset);
        let mut state = self.state.lock().unwrap();
        state
            .pages
            .get_mut(&first_page_address)
            .expect("first kernel page must be inserted")[first_offset..first_offset + first_count]
            .copy_from_slice(&bytes[..first_count]);
        if first_count < bytes.len() {
            state
                .pages
                .get_mut(&second_page_address)
                .expect("second kernel page must be inserted")[..bytes.len() - first_count]
                .copy_from_slice(&bytes[first_count..]);
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
                // Linux supplies a kernel virtual pointer alongside the physical traversal link.
                page.next = 0xffff_8000_0000_0000 + next_address;
                page.next_pa = next_address;
            }
            state.pages.insert(
                page_addresses[index],
                page.as_bytes().try_into().expect("HekiPage is one page"),
            );
        }

        (page_addresses[0], ranges.len() as u64)
    }

    pub(super) fn overwrite_heki_page(&self, address: u64, page: &HekiPage) {
        assert_eq!(
            address % PAGE_SIZE as u64,
            0,
            "page address must be aligned"
        );
        self.state.lock().unwrap().pages.insert(
            address,
            page.as_bytes().try_into().expect("HekiPage is one page"),
        );
    }

    pub(super) fn protection_operations(&self) -> Vec<(u64, u64, MemAttr)> {
        self.state.lock().unwrap().protection_operations.clone()
    }
}

struct MockFrameTxn {
    state: Arc<Mutex<MockVtl0State>>,
    owned_ranges: BTreeSet<(u64, u64)>,
    new_ranges: Vec<(u64, u64)>,
    protection_updates: BTreeMap<(u64, u64), MemAttr>,
    committed: bool,
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
        let mut state = self.state.lock().unwrap();
        let mut seen = BTreeSet::new();
        let mut statuses = Vec::with_capacity(ranges.len());
        for range in ranges {
            let requested = normalized_range(*range);
            let status = if requested.0 >= requested.1 {
                Ok(ReservationStatus::AlreadyOwned)
            } else if ranges_overlap(&seen, requested) {
                Err(VsmError::ProtectedFrameOverlap)
            } else if ranges_cover(&owned_before, requested) {
                Ok(ReservationStatus::AlreadyOwned)
            } else if ranges_overlap(&owned_before, requested)
                || ranges_overlap(&state.owned_ranges, requested)
            {
                Err(VsmError::ProtectedFrameOverlap)
            } else {
                Ok(ReservationStatus::New)
            };
            let status = match status {
                Ok(status) => status,
                Err(error) => {
                    for &range in &self.new_ranges[new_ranges_before..] {
                        subtract_ranges(&mut state.owned_ranges, range);
                    }
                    self.owned_ranges = owned_before;
                    self.new_ranges.truncate(new_ranges_before);
                    return Err(error);
                }
            };
            insert_range(&mut seen, requested);
            if status == ReservationStatus::New {
                insert_range(&mut self.owned_ranges, requested);
                self.new_ranges.push(requested);
                insert_range(&mut state.owned_ranges, requested);
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

impl Drop for MockFrameTxn {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut state = self.state.lock().unwrap();
        for &range in &self.new_ranges {
            subtract_ranges(&mut state.owned_ranges, range);
        }
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
            committed: false,
        };
        txn.reserve(initial)?;
        f(&mut txn)?;

        let mut state = self.state.lock().unwrap();
        if txn
            .protection_updates
            .keys()
            .any(|&range| !ranges_cover(&txn.owned_ranges, range))
        {
            return Err(VsmError::ProtectedFrameOverlap);
        }
        for (&range, &attr) in &txn.protection_updates {
            apply_protection(&mut state.protections, range, attr);
            if attr.contains(MemAttr::MEM_ATTR_WRITE) {
                subtract_ranges(&mut state.owned_ranges, range);
            } else {
                insert_range(&mut state.owned_ranges, range);
            }
        }
        txn.committed = true;
        Ok(())
    }

    fn install_ringbuffer(&self, _pa: u64, _size: u64) {}

    fn end_of_boot_reached(&self) -> bool {
        false
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        Ok(())
    }
}
