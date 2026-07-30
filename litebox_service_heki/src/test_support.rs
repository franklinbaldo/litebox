// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use std::{
    collections::BTreeMap,
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
}

struct MockFrameTxn<'a> {
    gate: &'a MockVtl0Gate,
}

impl FrameTxn for MockFrameTxn<'_> {
    fn reserve(
        &mut self,
        ranges: &[PhysFrameRange<Size4KiB>],
    ) -> Result<Vec<ReservationStatus>, VsmError> {
        Ok(core::iter::repeat_n(ReservationStatus::New, ranges.len()).collect())
    }

    fn protect(&mut self, range: PhysFrameRange<Size4KiB>, attr: MemAttr) -> Result<(), VsmError> {
        self.gate.protect_frame(range, attr)
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
        _range: PhysFrameRange<Size4KiB>,
        _attr: MemAttr,
    ) -> Result<(), VsmError> {
        Ok(())
    }

    fn unprotect_frames(&self, _range: PhysFrameRange<Size4KiB>) -> Result<(), VsmError> {
        Ok(())
    }

    fn protect_frames_transactionally(
        &self,
        initial: &[PhysFrameRange<Size4KiB>],
        f: &mut dyn FnMut(&mut dyn FrameTxn) -> Result<(), VsmError>,
    ) -> Result<(), VsmError> {
        let mut txn = MockFrameTxn { gate: self };
        let _ = txn.reserve(initial)?;
        f(&mut txn)
    }

    fn install_ringbuffer(&self, _pa: u64, _size: u64) {}

    fn end_of_boot_reached(&self) -> bool {
        false
    }

    fn lock_control_registers(&self) -> Result<(), VsmError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MockVtl0Gate;
    use litebox_common_linux::vmap::PhysPageAddr;
    use litebox_common_lvbs::{PAGE_SIZE, VsmError, Vtl0Gate};

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
}
