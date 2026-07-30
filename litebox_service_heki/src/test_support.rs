// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    vec::Vec,
};

use litebox_common_linux::vmap::PhysPageAddr;
use litebox_common_lvbs::{FrameTxn, MemAttr, PAGE_SIZE, ReservationStatus, VsmError, Vtl0Gate};
use x86_64::structures::paging::{Size4KiB, frame::PhysFrameRange};

#[derive(Clone, Default)]
pub(super) struct MockVtl0Gate {
    state: Arc<Mutex<MockVtl0State>>,
}

#[derive(Default)]
struct MockVtl0State {
    pages: BTreeMap<u64, [u8; PAGE_SIZE]>,
    owned_ranges: BTreeSet<(u64, u64)>,
    protections: BTreeMap<(u64, u64), MemAttr>,
    ringbuffer: Option<(u64, u64)>,
    end_of_boot_reached: bool,
    control_registers_locked: bool,
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

    pub(super) fn ringbuffer(&self) -> Option<(u64, u64)> {
        self.state.lock().unwrap().ringbuffer
    }

    pub(super) fn set_end_of_boot_reached(&self) {
        self.state.lock().unwrap().end_of_boot_reached = true;
    }

    pub(super) fn control_registers_locked(&self) -> bool {
        self.state.lock().unwrap().control_registers_locked
    }
}

struct MockFrameTxn {
    owned_ranges: BTreeSet<(u64, u64)>,
    protections: BTreeMap<(u64, u64), MemAttr>,
}

fn normalized_range(range: PhysFrameRange<Size4KiB>) -> (u64, u64) {
    (
        range.start.start_address().as_u64(),
        range.end.start_address().as_u64(),
    )
}

fn reserve_range(
    owned_ranges: &mut BTreeSet<(u64, u64)>,
    range: PhysFrameRange<Size4KiB>,
) -> Result<ReservationStatus, VsmError> {
    let requested = normalized_range(range);
    if owned_ranges.contains(&requested) || requested.0 >= requested.1 {
        return Ok(ReservationStatus::AlreadyOwned);
    }
    if owned_ranges
        .iter()
        .any(|&(start, end)| requested.0 < end && start < requested.1)
    {
        return Err(VsmError::ProtectedFrameOverlap);
    }
    owned_ranges.insert(requested);
    Ok(ReservationStatus::New)
}

impl FrameTxn for MockFrameTxn {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        let previous = self.owned_ranges.clone();
        let result: Result<Vec<_>, _> = ranges
            .iter()
            .copied()
            .map(|range| reserve_range(&mut self.owned_ranges, range))
            .collect();
        if result.is_err() {
            self.owned_ranges = previous;
        }
        result
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        let range = normalized_range(range);
        if !self.owned_ranges.contains(&range) {
            return Err(VsmError::ProtectedFrameOverlap);
        }
        self.protections.insert(range, attr);
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
        state.owned_ranges.insert(range);
        state.protections.insert(range, attr);
        Ok(())
    }

    fn unprotect_frames(&self, range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        let mut state = self.state.lock().unwrap();
        let range = normalized_range(range);
        state.owned_ranges.remove(&range);
        state.protections.remove(&range);
        Ok(())
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let (owned_ranges, protections) = {
            let state = self.state.lock().unwrap();
            (state.owned_ranges.clone(), state.protections.clone())
        };
        let mut txn = MockFrameTxn {
            owned_ranges,
            protections,
        };
        txn.reserve(initial)?;
        f(&mut txn)?;

        let mut state = self.state.lock().unwrap();
        state.owned_ranges = txn.owned_ranges;
        state.protections = txn.protections;
        Ok(())
    }

    fn install_ringbuffer(&self, pa: u64, size: u64) {
        self.state.lock().unwrap().ringbuffer = Some((pa, size));
    }

    fn end_of_boot_reached(&self) -> bool {
        self.state.lock().unwrap().end_of_boot_reached
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        self.state.lock().unwrap().control_registers_locked = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MockVtl0Gate;
    use alloc::vec;
    use litebox_common_linux::vmap::PhysPageAddr;
    use litebox_common_lvbs::{MemAttr, PAGE_SIZE, ReservationStatus, VsmError, Vtl0Gate};
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
    fn transaction_reserve_reports_new_and_already_owned_consistently() {
        let gate = MockVtl0Gate::new();
        let existing = frame_range(0x10000, 0x11000);
        let fresh = frame_range(0x12000, 0x13000);
        gate.protect_frames_transactionally(&[existing], &mut |_| Ok(()))
            .unwrap();

        gate.protect_frames_transactionally(&[], &mut |txn| {
            assert_eq!(
                txn.reserve(&[existing, fresh])?,
                vec![ReservationStatus::AlreadyOwned, ReservationStatus::New]
            );
            assert_eq!(
                txn.reserve(&[existing, fresh])?,
                vec![
                    ReservationStatus::AlreadyOwned,
                    ReservationStatus::AlreadyOwned
                ]
            );
            Ok(())
        })
        .unwrap();

        assert_eq!(
            gate.owned_ranges(),
            vec![(0x10000, 0x11000), (0x12000, 0x13000)]
        );
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
