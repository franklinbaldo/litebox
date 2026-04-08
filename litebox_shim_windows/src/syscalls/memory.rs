// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT virtual memory syscall handlers.
//!
//! Implements NtAllocateVirtualMemory, NtFreeVirtualMemory,
//! NtProtectVirtualMemory, and NtQueryVirtualMemory on top of
//! the LiteBox PageManager.

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox::platform::RawPointerProvider;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox_common_windows::nt_types::{mem_alloc_type, mem_protect, mem_state};
use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

use super::NtSyscallArgs;

const PAGE_SIZE: usize = 4096;
const ALLOCATION_GRANULARITY: usize = 0x10000;

fn align_up(value: usize, align: usize) -> Option<usize> {
    let addend = align.checked_sub(1)?;
    value.checked_add(addend).map(|v| v & !addend)
}

/// Helper to create a platform raw mutable pointer from a usize address.
fn raw_mut_ptr(addr: usize) -> <Platform as RawPointerProvider>::RawMutPointer<u8> {
    <Platform as RawPointerProvider>::RawMutPointer::from_usize(addr)
}

fn validate_readable_input_buffer(
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    ptr: usize,
    len: usize,
) -> bool {
    if ptr == 0 || len == 0 {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    let aligned_base = ptr & !(PAGE_SIZE - 1);
    let aligned_size = (end - aligned_base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let (Some(addr), Some(size)) = (
        NonZeroAddress::<PAGE_SIZE>::new(aligned_base),
        NonZeroPageSize::<PAGE_SIZE>::new(aligned_size),
    ) else {
        return false;
    };
    pm.get_memory_permissions(addr, size)
        .is_some_and(|perms| perms.contains(MemoryRegionPermissions::READ))
}

fn validate_read_write_input_buffer(
    pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>,
    ptr: usize,
    len: usize,
) -> bool {
    if ptr == 0 || len == 0 {
        return false;
    }
    let Some(end) = ptr.checked_add(len) else {
        return false;
    };
    let aligned_base = ptr & !(PAGE_SIZE - 1);
    let aligned_size = (end - aligned_base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let (Some(addr), Some(size)) = (
        NonZeroAddress::<PAGE_SIZE>::new(aligned_base),
        NonZeroPageSize::<PAGE_SIZE>::new(aligned_size),
    ) else {
        return false;
    };
    pm.get_memory_permissions(addr, size).is_some_and(|perms| {
        perms.contains(MemoryRegionPermissions::READ)
            && perms.contains(MemoryRegionPermissions::WRITE)
    })
}

fn read_guest_usize(ptr: usize) -> Result<usize, NtStatus> {
    crate::try_read_guest_value_unaligned::<usize>(ptr).ok_or(NtStatus::STATUS_ACCESS_VIOLATION)
}

fn read_guest_u64(ptr: usize) -> Result<u64, NtStatus> {
    crate::try_read_guest_value_unaligned::<u64>(ptr).ok_or(NtStatus::STATUS_ACCESS_VIOLATION)
}

fn write_guest_usize(ptr: usize, value: usize) -> Result<(), NtStatus> {
    crate::try_write_guest_value_unaligned::<usize>(ptr, value)
        .then_some(())
        .ok_or(NtStatus::STATUS_ACCESS_VIOLATION)
}

fn write_base_and_region(
    base_addr_ptr: usize,
    region_size_ptr: usize,
    base: usize,
    size: usize,
) -> Result<(), NtStatus> {
    write_guest_usize(base_addr_ptr, base)?;
    write_guest_usize(region_size_ptr, size)
}

macro_rules! nt_try {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}

fn protect_overlapping_pm_subranges(
    vmem: &mut litebox::mm::linux::Vmem<Platform, PAGE_SIZE>,
    base: usize,
    size: usize,
    perms: MemoryRegionPermissions,
    require_full_coverage: bool,
) -> Result<bool, NtStatus> {
    let end = base
        .checked_add(size)
        .ok_or(NtStatus::STATUS_INVALID_PARAMETER)?;
    let overlapping: alloc::vec::Vec<_> = vmem
        .overlapping(base..end)
        .map(|(range, vma)| {
            (
                range.start.max(base),
                range.end.min(end),
                MemoryRegionPermissions::from(vma.flags()),
            )
        })
        .filter(|(s, e, _)| e > s)
        .collect();

    if overlapping.is_empty() {
        if require_full_coverage {
            return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
        }
        return Ok(false);
    }

    if require_full_coverage {
        let mut cursor = base;
        for (s, e, _) in &overlapping {
            if *s > cursor {
                return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
            }
            cursor = *e;
        }
        if cursor < end {
            return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
        }
    }

    let mut applied: alloc::vec::Vec<(usize, usize, MemoryRegionPermissions)> =
        alloc::vec::Vec::new();
    for (s, e, old_perms) in overlapping {
        if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(s, e) {
            // Safety: caller holds the PM write lock and requested range is page-aligned.
            if unsafe { vmem.protect_mapping(pr, perms) }.is_err() {
                for (rb_start, rb_end, rb_perms) in applied.into_iter().rev() {
                    if let Some(rb_pr) =
                        litebox::mm::linux::PageRange::<PAGE_SIZE>::new(rb_start, rb_end)
                    {
                        let _ = unsafe { vmem.protect_mapping(rb_pr, rb_perms) };
                    }
                }
                return Err(NtStatus::STATUS_INVALID_PAGE_PROTECTION);
            }
            applied.push((s, e, old_perms));
        }
    }

    Ok(!applied.is_empty())
}

/// Materialize unmapped holes in `[base, base+size)` by creating pages
/// directly via [`Vmem`], with rollback on failure.  Must be called while
/// the PM write lock is held (i.e. inside a [`with_memory`] closure).
fn materialize_va_commit_pages(
    vmem: &mut litebox::mm::linux::Vmem<Platform, PAGE_SIZE>,
    base: usize,
    size: usize,
    protect: u32,
) -> Result<(), ()> {
    let page_op = nt_protect_to_page_op(protect);
    if matches!(page_op, PageOp::NoAccess) {
        return Ok(());
    }

    let perms = page_op_to_permissions(page_op);
    let end = base.checked_add(size).ok_or(())?;

    // Collect existing mappings overlapping [base, end) to identify holes.
    let existing: alloc::vec::Vec<(usize, usize)> = vmem
        .overlapping(base..end)
        .map(|(range, _)| (range.start, range.end))
        .collect();

    // Compute holes — sub-ranges of [base, end) not covered by any mapping.
    let mut holes: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
    let mut cursor = base;
    for (r_start, r_end) in &existing {
        if cursor < *r_start {
            holes.push((cursor, *r_start - cursor));
        }
        cursor = cursor.max((*r_end).min(end));
        if cursor >= end {
            break;
        }
    }
    if cursor < end {
        holes.push((cursor, end - cursor));
    }

    // Create pages for each hole, rolling back on failure.
    let mut created: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
    for &(hole_base, hole_size) in &holes {
        let (Some(nz_addr), Some(nz_size)) = (
            NonZeroAddress::<PAGE_SIZE>::new(hole_base),
            NonZeroPageSize::<PAGE_SIZE>::new(hole_size),
        ) else {
            rollback_created_pages(vmem, created);
            return Err(());
        };
        let flags = CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE;
        // Safety: address and size are page-aligned and NOREPLACE prevents
        // clobbering existing mappings.
        match unsafe { vmem.create_pages(Some(nz_addr), nz_size, flags, perms) } {
            Ok(_) => created.push((hole_base, hole_size)),
            Err(_) => {
                rollback_created_pages(vmem, created);
                return Err(());
            }
        }
    }

    Ok(())
}

/// Remove pages previously created by [`materialize_va_commit_pages`] during
/// error rollback.
fn rollback_created_pages(
    vmem: &mut litebox::mm::linux::Vmem<Platform, PAGE_SIZE>,
    ranges: alloc::vec::Vec<(usize, usize)>,
) {
    for (rb_base, rb_size) in ranges.into_iter().rev() {
        if let Some(pr) =
            litebox::mm::linux::PageRange::<PAGE_SIZE>::new(rb_base, rb_base + rb_size)
        {
            // Safety: removing pages we just created during this call.
            let _ = unsafe { vmem.remove_mapping(pr) };
        }
    }
}

/// NtAllocateVirtualMemory — allocate or commit pages in the guest address space.
///
/// NT signature:
/// ```text
/// NTSTATUS NtAllocateVirtualMemory(
///     HANDLE ProcessHandle,     // r10
///     PVOID *BaseAddress,       // rdx (in/out)
///     ULONG_PTR ZeroBits,       // r8
///     PSIZE_T RegionSize,       // r9 (in/out)
///     ULONG AllocationType,     // [rsp+0x28]
///     ULONG Protect             // [rsp+0x30]
/// );
/// ```
pub(crate) fn nt_allocate_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    // Read in/out pointers from registers.
    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg3; // PSIZE_T RegionSize

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Read the requested base address and size from guest memory.
    // Safety: these are guest-accessible pointers (userland shares address space).
    if !validate_read_write_input_buffer(pm, base_addr_ptr, core::mem::size_of::<usize>())
        || !validate_read_write_input_buffer(pm, region_size_ptr, core::mem::size_of::<usize>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let requested_base = nt_try!(read_guest_usize(base_addr_ptr));
    let requested_size = nt_try!(read_guest_usize(region_size_ptr));

    // Read stack args: AllocationType at [rsp+0x28], Protect at [rsp+0x30]
    let alloc_type = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let protect = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x30).unwrap_or(0);

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RESET: u32 = 0x80000;

    if requested_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // MEM_RESET is a hint that the caller doesn't need the page contents.
    // Real Windows requires the range to be committed — reject if not.
    if (alloc_type & MEM_RESET) != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        let Some(aligned_size) = align_up(requested_size, PAGE_SIZE) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if aligned_size == 0 || aligned_base == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let last_page = aligned_base + aligned_size - PAGE_SIZE;
        let committed_ok = ps.with_memory_read(|vmem, mem| {
            let is_page_committed = |page: usize| -> bool {
                if let Some(page_range) =
                    litebox::mm::linux::PageRange::<PAGE_SIZE>::new(page, page + PAGE_SIZE)
                {
                    if let Some(perms) = vmem.get_memory_permissions(page_range) {
                        return !perms.is_empty()
                            || (mem.tracked_alloc_at(page).is_some()
                                && !mem.pm_is_decommitted(page));
                    }
                }
                mem.va_committed_protect(page).is_some()
            };
            if !is_page_committed(aligned_base) {
                return false;
            }
            if last_page != aligned_base && !is_page_committed(last_page) {
                return false;
            }
            true
        });
        if !committed_ok {
            return NtStatus(0xC000_0018u32 as i32);
        }
        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            aligned_base,
            aligned_size
        ));
        return NtStatus::STATUS_SUCCESS;
    }

    let has_commit = (alloc_type & MEM_COMMIT) != 0;
    let has_reserve = (alloc_type & MEM_RESERVE) != 0;
    let Some(aligned_size) = align_up(requested_size, PAGE_SIZE) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };
    let reservation_size = if has_reserve {
        let Some(size) = align_up(requested_size, ALLOCATION_GRANULARITY) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        size
    } else {
        aligned_size
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtAllocateVirtualMemory request: base=0x{requested_base:X} size=0x{:X} type=0x{alloc_type:X} prot=0x{protect:X}\n",
            if has_reserve {
                reservation_size
            } else {
                aligned_size
            },
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    // MEM_COMMIT without MEM_RESERVE: commit pages inside an existing
    // reservation, or upgrade permissions on already-committed pages.
    if has_commit && !has_reserve && requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);

        // Check if this commit falls entirely inside a VA-only reservation.
        // Materialize currently unmapped holes so the guest sees committed
        // pages immediately instead of round-tripping through the user-mode
        // VEH demand-page path on first touch.
        //
        // All operations (reservation check, page creation, permission
        // normalization, metadata update) are performed under a single write
        // lock to close the TOCTOU gap between the check and the mutation.
        let va_commit_result: Option<Result<(), NtStatus>> = ps.with_memory(|vmem, mem| {
            mem.va_reservation_contains_range(aligned_base, aligned_size)?;
            if materialize_va_commit_pages(vmem, aligned_base, aligned_size, protect).is_err() {
                return Some(Err(NtStatus::STATUS_NO_MEMORY));
            }

            // Mixed-state reservations are common on Windows heaps: some pages
            // may already exist in PM while nearby pages are still reservation
            // bookkeeping only. Normalize permissions across every overlapping PM
            // subrange, then record the commit only after all protections succeed.
            let perms = page_op_to_permissions(nt_protect_to_page_op(protect));
            let commit_end = aligned_base + aligned_size;
            let overlapping: alloc::vec::Vec<_> = vmem
                .overlapping(aligned_base..commit_end)
                .map(|(range, _)| (range.start, range.end))
                .collect();
            for (start, end) in overlapping {
                let s = start.max(aligned_base);
                let e = end.min(commit_end);
                if e > s {
                    if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(s, e) {
                        // Safety: range is within the committed VA reservation.
                        if unsafe { vmem.protect_mapping(pr, perms) }.is_err() {
                            return Some(Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED));
                        }
                    }
                }
            }
            mem.va_commit(aligned_base, aligned_size, protect);
            Some(Ok(()))
        });
        match va_commit_result {
            Some(Ok(())) => {
                nt_try!(write_base_and_region(
                    base_addr_ptr,
                    region_size_ptr,
                    aligned_base,
                    aligned_size
                ));
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtAllocateVirtualMemory → OK (MEM_COMMIT in VA reservation) base=0x{aligned_base:X} size=0x{aligned_size:X}\n",
                    ));
                }
                return NtStatus::STATUS_SUCCESS;
            }
            Some(Err(status)) => return status,
            None => {} // not in a reservation, fall through
        }

        // Not inside a VA reservation — upgrade existing PM pages.
        // Perform permission check, protection change, and metadata update
        // under a single write lock to prevent races with concurrent
        // MEM_DECOMMIT or demand-fault operations.
        let pm_commit_result: Result<(), NtStatus> = ps.with_memory(|vmem, mem| {
            let commit_end = aligned_base.saturating_add(aligned_size);
            if vmem.overlapping(aligned_base..commit_end).next().is_none() {
                return Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED);
            }
            let perms = page_op_to_permissions(nt_protect_to_page_op(protect));
            // require_full_coverage=true ensures the entire range is PM-backed.
            protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, perms, true)?;
            mem.pm_recommit(aligned_base, aligned_size);
            Ok(())
        });
        match pm_commit_result {
            Ok(()) => {}
            Err(status) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtAllocateVirtualMemory MEM_COMMIT FAILED base=0x{aligned_base:X} size=0x{aligned_size:X}\n"
                    ));
                }
                return status;
            }
        }
        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            aligned_base,
            aligned_size
        ));
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemory → OK (MEM_COMMIT) base=0x{aligned_base:X} size=0x{aligned_size:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    if has_reserve {
        // Reserve + optionally commit under a single write lock to prevent
        // any concurrent operation from seeing the reservation before its
        // pages are materialized.
        let reserve_result: Result<(usize, bool), NtStatus> = ps.with_memory(|vmem, mem| {
            let pm_mappings: alloc::vec::Vec<_> = vmem
                .iter()
                .map(|(r, vma)| (r.clone(), vma.flags()))
                .collect();
            let reserved_base = mem.va_reserve(&pm_mappings, requested_base, reservation_size, 0);
            if reserved_base == 0 {
                return Err(NtStatus::STATUS_NO_MEMORY);
            }

            if has_commit {
                if materialize_va_commit_pages(vmem, reserved_base, aligned_size, protect).is_err()
                {
                    let _ = mem.va_unreserve(reserved_base);
                    return Err(NtStatus::STATUS_NO_MEMORY);
                }
                mem.va_commit(reserved_base, aligned_size, protect);
            }
            Ok((reserved_base, has_commit))
        });
        let (reserved_base, committed) = match reserve_result {
            Ok(v) => v,
            Err(status) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtAllocateVirtualMemory → STATUS_NO_MEMORY (req_base=0x{requested_base:X}, size=0x{reservation_size:X})\n"
                    ));
                }
                return status;
            }
        };

        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            reserved_base,
            if has_commit {
                aligned_size
            } else {
                reservation_size
            },
        ));
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemory → OK{} base=0x{reserved_base:X} size=0x{:X}\n",
                if has_commit {
                    " (MEM_RESERVE|MEM_COMMIT)"
                } else {
                    " (MEM_RESERVE)"
                },
                if has_commit {
                    aligned_size
                } else {
                    reservation_size
                },
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(nz_size) = NonZeroPageSize::new(aligned_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    // When a specific base address is requested, use NOREPLACE to prevent
    // silently overwriting existing allocations (DLLs, heap segments, etc.).
    // MEM_COMMIT-only is handled above (upgrade path) and never reaches here.
    let flags = if requested_base != 0 {
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE
    } else {
        CreatePagesFlags::empty()
    };

    let suggested = if requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        NonZeroAddress::new(aligned_base)
    } else {
        None
    };

    // MEM_COMMIT fallthrough (reserve-only is handled above via va_reserve):
    // allocate host-backed pages via PM.
    let page_op = nt_protect_to_page_op(protect);
    let result = match page_op {
        PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
            pm.create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::ReadOnly => unsafe {
            pm.create_readable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::Execute | PageOp::ExecuteRead => unsafe {
            pm.create_executable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::NoAccess => unsafe {
            pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0))
        },
    };

    match result {
        Ok(ptr) => {
            let allocated_addr = ptr.as_usize();
            if matches!(page_op, PageOp::ExecuteReadWrite)
                && unsafe { pm.make_pages_rwx(ptr, aligned_size) }.is_err()
            {
                let _ = unsafe { pm.remove_pages(ptr, aligned_size) };
                return NtStatus::STATUS_INVALID_PAGE_PROTECTION;
            }
            ps.with_memory(|_vmem, mem| mem.track_alloc(allocated_addr, aligned_size, protect));
            write_guest_usize(base_addr_ptr, allocated_addr).ok();
            write_guest_usize(region_size_ptr, aligned_size).ok();
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemory → OK base=0x{allocated_addr:X} size=0x{aligned_size:X}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemory → STATUS_NO_MEMORY (req_base=0x{requested_base:X}, size=0x{aligned_size:X})\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NO_MEMORY
        }
    }
}

/// NtAllocateVirtualMemoryEx — extended allocation (segment heap uses this).
///
/// ```text
/// NTSTATUS NtAllocateVirtualMemoryEx(
///     HANDLE ProcessHandle,           // r10
///     PVOID *BaseAddress,             // rdx (in/out)
///     PSIZE_T RegionSize,             // r8 (in/out)
///     ULONG AllocationType,           // r9
///     ULONG PageProtection,           // [rsp+0x28]
///     MEM_EXTENDED_PARAMETER *Params, // [rsp+0x30]
///     ULONG ParamCount                // [rsp+0x38]
/// );
/// ```
pub(crate) fn nt_allocate_virtual_memory_ex(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    // Note: parameter layout differs from NtAllocateVirtualMemory!
    // arg2 (r8) = RegionSize* (not ZeroBits)
    // arg3 (r9) = AllocationType (not RegionSize*)
    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg2; // PSIZE_T RegionSize (r8, not r9!)
    let alloc_type = args.arg3 as u32; // ULONG AllocationType (r9)
    let protect = crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x28).unwrap_or(0);

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    if !validate_read_write_input_buffer(pm, base_addr_ptr, core::mem::size_of::<usize>())
        || !validate_read_write_input_buffer(pm, region_size_ptr, core::mem::size_of::<usize>())
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let requested_base = nt_try!(read_guest_usize(base_addr_ptr));
    let requested_size = nt_try!(read_guest_usize(region_size_ptr));

    // Read extended parameters from stack.
    let ext_params_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);
    let ext_params_count =
        crate::try_read_guest_value_unaligned::<u32>(ctx.regs.rsp + 0x38).unwrap_or(0);

    // Parse MEM_ADDRESS_REQUIREMENTS from extended parameters.
    // MEM_EXTENDED_PARAMETER is 16 bytes: { Type: ULONG64, Value: ULONG64 }
    // Type 1 = MemExtendedParameterAddressRequirements → Value is a pointer to:
    //   struct MEM_ADDRESS_REQUIREMENTS {
    //       PVOID  LowestStartingAddress;  // +0x00
    //       PVOID  HighestEndingAddress;   // +0x08
    //       SIZE_T Alignment;             // +0x10
    //   }
    let mut required_alignment: usize = 0;
    let mut lowest_address: usize = 0;
    let mut highest_address: usize = 0;
    if ext_params_count > 0 && ext_params_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }
    if ext_params_ptr != 0 && ext_params_count > 0 {
        let ext_param_count = ext_params_count.min(8) as usize;
        let Some(ext_params_len) = ext_param_count.checked_mul(16) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if !validate_readable_input_buffer(pm, ext_params_ptr, ext_params_len) {
            return NtStatus::STATUS_ACCESS_VIOLATION;
        }
        for i in 0..ext_param_count {
            let param_addr = ext_params_ptr + i * 16;
            let param_type = nt_try!(read_guest_u64(param_addr));
            let param_value = nt_try!(read_guest_u64(param_addr + 8));
            // Type field low 8 bits = parameter type, bits 63:8 are reserved/flags.
            if (param_type & 0xFF) == 1 && param_value != 0 {
                // MemExtendedParameterAddressRequirements: value is pointer
                let req_ptr = param_value as usize;
                if !validate_readable_input_buffer(pm, req_ptr, 0x18) {
                    return NtStatus::STATUS_ACCESS_VIOLATION;
                }
                lowest_address = nt_try!(read_guest_usize(req_ptr));
                highest_address = nt_try!(read_guest_usize(req_ptr + 8));
                required_alignment = nt_try!(read_guest_usize(req_ptr + 0x10));
            }
        }
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtAllocateVirtualMemoryEx(base=0x{requested_base:X}, size=0x{requested_size:X}, type=0x{alloc_type:X}, prot=0x{protect:X}, ext=0x{ext_params_ptr:X}, count={ext_params_count})\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        if required_alignment != 0 || lowest_address != 0 || highest_address != 0 {
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "  MEM_ADDRESS_REQUIREMENTS: lowest=0x{lowest_address:X} highest=0x{highest_address:X} align=0x{required_alignment:X}\n"
            ));
        }

        // Dump extended parameters if present.
        if ext_params_ptr != 0 && ext_params_count > 0 {
            for i in 0..ext_params_count.min(8) {
                let param_addr = ext_params_ptr + (i as usize) * 16;
                let param_type = read_guest_u64(param_addr).unwrap_or(0);
                let param_value = read_guest_u64(param_addr + 8).unwrap_or(0);
                let msg =
                    alloc::format!("  ext[{i}]: type=0x{param_type:X} value=0x{param_value:X}\n");
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
        }
    }

    if requested_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }
    if required_alignment != 0 && !required_alignment.is_power_of_two() {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RESET: u32 = 0x80000;

    // MEM_RESET is a hint that the caller doesn't need the page contents.
    // Real Windows requires the range to be committed — reject if not.
    if (alloc_type & MEM_RESET) != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        let Some(aligned_size) = align_up(requested_size, PAGE_SIZE) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if aligned_size == 0 || aligned_base == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let last_page = aligned_base + aligned_size - PAGE_SIZE;
        let committed_ok = ps.with_memory_read(|vmem, mem| {
            let is_page_committed = |page: usize| -> bool {
                if let Some(page_range) =
                    litebox::mm::linux::PageRange::<PAGE_SIZE>::new(page, page + PAGE_SIZE)
                {
                    if let Some(perms) = vmem.get_memory_permissions(page_range) {
                        return !perms.is_empty()
                            || (mem.tracked_alloc_at(page).is_some()
                                && !mem.pm_is_decommitted(page));
                    }
                }
                mem.va_committed_protect(page).is_some()
            };
            if !is_page_committed(aligned_base) {
                return false;
            }
            if last_page != aligned_base && !is_page_committed(last_page) {
                return false;
            }
            true
        });
        if !committed_ok {
            return NtStatus(0xC000_0018u32 as i32);
        }
        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            aligned_base,
            aligned_size
        ));
        return NtStatus::STATUS_SUCCESS;
    }

    let has_commit = (alloc_type & MEM_COMMIT) != 0;
    let has_reserve = (alloc_type & MEM_RESERVE) != 0;
    let Some(aligned_size) = align_up(requested_size, PAGE_SIZE) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };
    // Honor MEM_ADDRESS_REQUIREMENTS alignment if specified and larger than
    // the default 64KB allocation granularity.
    let effective_granularity = if required_alignment > ALLOCATION_GRANULARITY {
        required_alignment
    } else {
        ALLOCATION_GRANULARITY
    };
    let reservation_size = if has_reserve {
        let Some(size) = align_up(requested_size, effective_granularity) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        size
    } else {
        aligned_size
    };

    // MEM_COMMIT without MEM_RESERVE: upgrade existing inaccessible pages.
    if has_commit && !has_reserve && requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);

        // If this commit falls entirely inside a VA-only reservation,
        // materialize any currently unmapped holes eagerly.  All operations
        // are performed under a single write lock to close the TOCTOU gap.
        let va_commit_result: Option<Result<(), NtStatus>> = ps.with_memory(|vmem, mem| {
            mem.va_reservation_contains_range(aligned_base, aligned_size)?;
            if materialize_va_commit_pages(vmem, aligned_base, aligned_size, protect).is_err() {
                return Some(Err(NtStatus::STATUS_NO_MEMORY));
            }
            let perms = page_op_to_permissions(nt_protect_to_page_op(protect));
            let commit_end = aligned_base + aligned_size;
            let overlapping: alloc::vec::Vec<_> = vmem
                .overlapping(aligned_base..commit_end)
                .map(|(range, _)| (range.start, range.end))
                .collect();
            for (start, end) in overlapping {
                let s = start.max(aligned_base);
                let e = end.min(commit_end);
                if e > s {
                    if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(s, e) {
                        // Safety: range is within the committed VA reservation.
                        if unsafe { vmem.protect_mapping(pr, perms) }.is_err() {
                            return Some(Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED));
                        }
                    }
                }
            }
            mem.va_commit(aligned_base, aligned_size, protect);
            Some(Ok(()))
        });
        match va_commit_result {
            Some(Ok(())) => {
                nt_try!(write_base_and_region(
                    base_addr_ptr,
                    region_size_ptr,
                    aligned_base,
                    aligned_size
                ));
                return NtStatus::STATUS_SUCCESS;
            }
            Some(Err(status)) => return status,
            None => {} // not in a reservation, fall through
        }

        // Not inside a VA reservation — upgrade existing PM pages.
        // Perform permission check, protection change, and metadata update
        // under a single write lock to prevent races.
        let pm_commit_result: Result<(), NtStatus> = ps.with_memory(|vmem, mem| {
            let commit_end = aligned_base + aligned_size;
            let has_mappings = vmem.overlapping(aligned_base..commit_end).next().is_some();
            if !has_mappings {
                return Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED);
            }
            let perms = page_op_to_permissions(nt_protect_to_page_op(protect));
            protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, perms, true)?;
            mem.pm_recommit(aligned_base, aligned_size);
            Ok(())
        });
        if let Err(status) = pm_commit_result {
            return status;
        }
        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            aligned_base,
            aligned_size
        ));
        return NtStatus::STATUS_SUCCESS;
    }

    // MEM_REPLACE_PLACEHOLDER (0x4000 in alloc context): replace an existing
    // placeholder (VA reservation) with committed pages.  V8 uses this with
    // type = MEM_COMMIT | MEM_RESERVE | MEM_REPLACE_PLACEHOLDER (0x7000).
    const MEM_REPLACE_PLACEHOLDER: u32 =
        litebox_common_windows::nt_types::mem_alloc_type::MEM_REPLACE_PLACEHOLDER;
    if (alloc_type & MEM_REPLACE_PLACEHOLDER) != 0 && has_commit && requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        // The range must lie inside an existing VA reservation (placeholder).
        // Check, remove placeholder, create pages, and track — all under one
        // write lock to close the TOCTOU gap between placeholder removal and
        // page creation.
        let replace_result = ps.with_memory(|vmem, mem| {
            if mem
                .va_reservation_contains_range(aligned_base, aligned_size)
                .is_none()
            {
                return Err(NtStatus::STATUS_CONFLICTING_ADDRESSES);
            }
            // Remove the placeholder portion — splits the reservation if needed.
            if !mem.va_remove_placeholder(aligned_base, aligned_size) {
                return Err(NtStatus::STATUS_CONFLICTING_ADDRESSES);
            }
            // Materialize committed pages.
            if materialize_va_commit_pages(vmem, aligned_base, aligned_size, protect).is_err() {
                // Roll back: re-insert the placeholder.
                mem.va_insert_reservation(aligned_base, aligned_size);
                return Err(NtStatus::STATUS_NO_MEMORY);
            }
            // Track the committed pages and the allocation for later release.
            mem.track_alloc(aligned_base, aligned_size, protect);
            Ok(())
        });
        if let Err(status) = replace_result {
            return status;
        }

        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            aligned_base,
            aligned_size
        ));
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemoryEx → OK (MEM_REPLACE_PLACEHOLDER) base=0x{aligned_base:X} size=0x{aligned_size:X}\n"
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    if has_reserve {
        // Reserve + optionally commit under a single write lock.
        let reserve_result: Result<(usize, bool), NtStatus> = ps.with_memory(|vmem, mem| {
            let pm_mappings: alloc::vec::Vec<_> = vmem
                .iter()
                .map(|(r, vma)| (r.clone(), vma.flags()))
                .collect();
            let reserved_base = mem.va_reserve_with_bounds(
                &pm_mappings,
                requested_base,
                reservation_size,
                effective_granularity,
                lowest_address,
                highest_address,
            );
            if reserved_base == 0 {
                return Err(NtStatus::STATUS_NO_MEMORY);
            }

            if has_commit {
                if materialize_va_commit_pages(vmem, reserved_base, aligned_size, protect).is_err()
                {
                    let _ = mem.va_unreserve(reserved_base);
                    return Err(NtStatus::STATUS_NO_MEMORY);
                }
                mem.va_commit(reserved_base, aligned_size, protect);
            }
            Ok((reserved_base, has_commit))
        });
        let (reserved_base, _committed) = match reserve_result {
            Ok(v) => v,
            Err(status) => {
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtAllocateVirtualMemoryEx → STATUS_NO_MEMORY (base=0x{requested_base:X}, size=0x{reservation_size:X})\n"
                    ));
                }
                return status;
            }
        };

        nt_try!(write_base_and_region(
            base_addr_ptr,
            region_size_ptr,
            reserved_base,
            if has_commit {
                aligned_size
            } else {
                reservation_size
            },
        ));
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "NT shim: NtAllocateVirtualMemoryEx → OK{} base=0x{reserved_base:X} size=0x{:X}\n",
                if has_commit {
                    " (MEM_RESERVE|MEM_COMMIT)"
                } else {
                    " (MEM_RESERVE)"
                },
                if has_commit {
                    aligned_size
                } else {
                    reservation_size
                },
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    let Some(nz_size) = NonZeroPageSize::new(aligned_size) else {
        return NtStatus::STATUS_INVALID_PARAMETER;
    };

    let flags = if requested_base != 0 {
        CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::NOREPLACE
    } else {
        CreatePagesFlags::empty()
    };

    let suggested = if requested_base != 0 {
        let aligned_base = requested_base & !(PAGE_SIZE - 1);
        NonZeroAddress::new(aligned_base)
    } else {
        None
    };

    let page_op = nt_protect_to_page_op(protect);
    let result = match page_op {
        PageOp::ReadWrite | PageOp::WriteCopy | PageOp::ExecuteReadWrite => unsafe {
            pm.create_writable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::ReadOnly => unsafe {
            pm.create_readable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::Execute | PageOp::ExecuteRead => unsafe {
            pm.create_executable_pages(suggested, nz_size, flags, |_| Ok(0))
        },
        PageOp::NoAccess => unsafe {
            pm.create_inaccessible_pages(suggested, nz_size, flags, |_| Ok(0))
        },
    };

    match result {
        Ok(ptr) => {
            let allocated_addr = ptr.as_usize();
            if matches!(page_op, PageOp::ExecuteReadWrite)
                && unsafe { pm.make_pages_rwx(ptr, aligned_size) }.is_err()
            {
                let _ = unsafe { pm.remove_pages(ptr, aligned_size) };
                return NtStatus::STATUS_INVALID_PAGE_PROTECTION;
            }
            ps.with_memory(|_vmem, mem| mem.track_alloc(allocated_addr, aligned_size, protect));
            nt_try!(write_base_and_region(
                base_addr_ptr,
                region_size_ptr,
                allocated_addr,
                aligned_size
            ));
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemoryEx → OK base=0x{allocated_addr:X} size=0x{aligned_size:X}\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_SUCCESS
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                let msg = alloc::format!(
                    "NT shim: NtAllocateVirtualMemoryEx → STATUS_NO_MEMORY (base=0x{requested_base:X}, size=0x{aligned_size:X})\n"
                );
                litebox_platform_multiplex::platform().debug_log_print(&msg);
            }
            NtStatus::STATUS_NO_MEMORY
        }
    }
}

/// NtFreeVirtualMemory — decommit or release pages.
///
/// NT signature:
/// ```text
/// NTSTATUS NtFreeVirtualMemory(
///     HANDLE ProcessHandle,   // r10
///     PVOID *BaseAddress,     // rdx (in/out)
///     PSIZE_T RegionSize,     // r8 (in/out)
///     ULONG FreeType          // r9
/// );
/// ```
pub(crate) fn nt_free_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);

    let base_addr_ptr = args.arg1; // PVOID *BaseAddress
    let region_size_ptr = args.arg2; // PSIZE_T RegionSize
    let free_type = args.arg3 as u32;

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let base = match read_guest_usize(base_addr_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let size = match read_guest_usize(region_size_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "NT shim: NtFreeVirtualMemory base=0x{base:X} size=0x{size:X} type=0x{free_type:X}\n"
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);
    }

    if base == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // ── Placeholder operations (Windows 10 1803+) ────────────────────────
    // These use the MEM_RELEASE bit combined with a low flag:
    //   0x8002 = MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER  → split / unplace
    //   0x8001 = MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS → merge placeholders
    use litebox_common_windows::nt_types::mem_alloc_type::{
        MEM_COALESCE_PLACEHOLDERS, MEM_PRESERVE_PLACEHOLDER,
    };

    if free_type == (mem_alloc_type::MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER) {
        // MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER (0x8002):
        // If the range is inside a VA reservation (placeholder), split it so
        // that [base, base+size) becomes a standalone placeholder.
        // If the range has committed (PM) pages, decommit them and create a
        // new placeholder reservation.
        let aligned_base = base & !(PAGE_SIZE - 1);
        let Some(aligned_size) = align_up(size, PAGE_SIZE) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if aligned_size == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        // Check-and-act atomically under a single write lock to avoid a
        // snapshot-then-mutate race between the reservation check and the
        // subsequent split/decommit.  PM page removal is also performed under
        // the same lock via vmem.remove_mapping().
        let split_result = ps.with_memory(|vmem, mem| {
            if mem.va_reservation_at(aligned_base).is_some() {
                // Split the reservation: keeps all pieces as separate placeholders.
                if !mem.va_split_placeholder(aligned_base, aligned_size) {
                    return Err(NtStatus::STATUS_CONFLICTING_ADDRESSES);
                }
                mem.va_decommit(aligned_base, aligned_size);
                Ok(true) // reservation split handled
            } else {
                // No reservation — committed pages being converted back to
                // placeholder.  Decommit the pages and create a reservation
                // entry, all under the same lock.
                let decommit_end = aligned_base.saturating_add(aligned_size);
                let overlapping: alloc::vec::Vec<_> = vmem
                    .overlapping(aligned_base..decommit_end)
                    .map(|(range, _)| (range.start.max(aligned_base), range.end.min(decommit_end)))
                    .filter(|(s, e)| e > s)
                    .collect();
                for (start, end) in overlapping {
                    if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(start, end) {
                        // Safety: removing committed pages within the decommit range.
                        let _ = unsafe { vmem.remove_mapping(pr) };
                    }
                }
                let _ = mem.release_tracked_alloc_range(aligned_base, aligned_size);
                mem.va_insert_reservation(aligned_base, aligned_size);
                mem.va_decommit(aligned_base, aligned_size);
                Ok(false) // PM decommit handled
            }
        });

        if let Err(status) = split_result {
            return status;
        }

        // Post-operation writeback: operation already completed, guest
        // pointers were validated at entry. Ignoring write failures is
        // acceptable — matches NT ProbeForWrite semantics where the
        // kernel writes inside try/except after the operation.
        write_guest_usize(base_addr_ptr, aligned_base).ok();
        write_guest_usize(region_size_ptr, aligned_size).ok();
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtFreeVirtualMemory MEM_PRESERVE_PLACEHOLDER base=0x{aligned_base:X} size=0x{aligned_size:X}\n",
            ));
        }
        return NtStatus::STATUS_SUCCESS;
    }

    if free_type == (mem_alloc_type::MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS) {
        // MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS (0x8001):
        // Merge adjacent placeholder (VA reservation) entries that cover
        // [base, base+size) into a single reservation.  Any committed pages
        // in the range are decommitted first.
        let aligned_base = base & !(PAGE_SIZE - 1);
        let Some(aligned_size) = align_up(size, PAGE_SIZE) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if aligned_size == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        // Decommit any PM pages in the range and update metadata — all under
        // a single write lock to close the TOCTOU gap.
        ps.with_memory(|vmem, mem| {
            let coalesce_end = aligned_base.saturating_add(aligned_size);
            let overlapping: alloc::vec::Vec<_> = vmem
                .overlapping(aligned_base..coalesce_end)
                .map(|(range, _)| (range.start.max(aligned_base), range.end.min(coalesce_end)))
                .filter(|(s, e)| e > s)
                .collect();
            for (start, end) in overlapping {
                if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(start, end) {
                    // Safety: removing committed pages within the coalesce range.
                    let _ = unsafe { vmem.remove_mapping(pr) };
                }
            }

            // Remove tracked allocation metadata if present.
            // Clear committed tracking.
            // Ensure we have a reservation entry covering the range, then merge.
            let _ = mem.release_tracked_alloc_range(aligned_base, aligned_size);
            mem.va_decommit(aligned_base, aligned_size);
            if mem.va_reservation_at(aligned_base).is_none() {
                mem.va_insert_reservation(aligned_base, aligned_size);
            }
            mem.va_coalesce_range(aligned_base, aligned_size);
        });

        write_guest_usize(base_addr_ptr, aligned_base).ok();
        write_guest_usize(region_size_ptr, aligned_size).ok();
        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: NtFreeVirtualMemory MEM_COALESCE_PLACEHOLDERS base=0x{aligned_base:X} size=0x{aligned_size:X}\n",
            ));
        }
        return NtStatus::STATUS_SUCCESS;
    }

    if free_type & mem_alloc_type::MEM_RELEASE != 0 {
        // MEM_RELEASE: free pages from the address space.
        // size == 0: release the entire original allocation.
        // size != 0: partial release (NT kernel allows this to shrink a VAD).

        // Check if this lies inside a reservation-backed allocation. Such
        // regions may legitimately contain PM-backed committed pages, but the
        // release semantics are still driven by the reservation metadata.
        //
        // All operations (reservation lookup, validation, PM removal, metadata
        // update) are performed under a single write lock to close the TOCTOU
        // gap between the reservation check and the mutation.
        let reservation_release: Option<Result<(usize, usize), NtStatus>> =
            ps.with_memory(|vmem, mem| {
                let (res_base, res_size) = mem.va_reservation_at(base)?;

                let (release_base, release_size) = if size == 0 {
                    // Whole-release still requires the original reservation base.
                    if base != res_base {
                        return Some(Err(NtStatus::STATUS_INVALID_PARAMETER));
                    }
                    (res_base, res_size)
                } else {
                    // Windows accepts partial MEM_RELEASE inside a reservation and
                    // rounds the request to page boundaries instead of insisting on
                    // whole-reservation release.
                    let release_base = base & !(PAGE_SIZE - 1);
                    let Some(release_end) = base
                        .checked_add(size)
                        .and_then(|end| align_up(end, PAGE_SIZE))
                    else {
                        return Some(Err(NtStatus::STATUS_INVALID_PARAMETER));
                    };
                    let release_size = release_end.saturating_sub(release_base);
                    if release_size == 0
                        || mem
                            .va_reservation_contains_range(release_base, release_size)
                            .is_none()
                    {
                        return Some(Err(NtStatus::STATUS_INVALID_PARAMETER));
                    }
                    (release_base, release_size)
                };

                // Remove any demand-faulted PM pages within the released sub-range.
                let release_end = release_base.saturating_add(release_size);
                let overlapping: alloc::vec::Vec<_> = vmem
                    .overlapping(release_base..release_end)
                    .map(|(range, _)| (range.start.max(release_base), range.end.min(release_end)))
                    .filter(|(s, e)| e > s)
                    .collect();
                for (start, end) in overlapping {
                    if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(start, end) {
                        // Safety: removing demand-faulted pages within the release range.
                        let _ = unsafe { vmem.remove_mapping(pr) };
                    }
                }

                let released = if size == 0 {
                    mem.va_unreserve(res_base).unwrap_or(0)
                } else {
                    mem.va_release_range(release_base, release_size)
                        .unwrap_or(0)
                };
                if released > 0 {
                    mem.clear_guard_pages(release_base, released);
                }
                Some(Ok((release_base, released)))
            });
        match reservation_release {
            Some(Ok((release_base, released_size))) => {
                if released_size == 0 {
                    return NtStatus::STATUS_INVALID_PARAMETER;
                }
                write_guest_usize(base_addr_ptr, release_base).ok();
                write_guest_usize(region_size_ptr, released_size).ok();
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtFreeVirtualMemory MEM_RELEASE (VA reservation) base=0x{release_base:X} size=0x{released_size:X}\n",
                    ));
                }
                return NtStatus::STATUS_SUCCESS;
            }
            Some(Err(status)) => return status,
            None => {} // not a reservation, fall through
        }

        // Non-reservation MEM_RELEASE: remove PM pages and update metadata
        // under a single write lock to prevent TOCTOU races.
        let release_result: Result<(usize, usize), NtStatus> = ps.with_memory(|vmem, mem| {
            let (release_size, tracked_release) = if size == 0 {
                match mem.tracked_alloc_at(base) {
                    Some((alloc_base, alloc_size, _)) if alloc_base == base => {
                        (alloc_size, Some((base, alloc_size)))
                    }
                    Some(_) => return Err(NtStatus::STATUS_INVALID_PARAMETER),
                    None => return Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED),
                }
            } else {
                let Some(aligned_release_size) = align_up(size, PAGE_SIZE) else {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                };
                let tracked_release = match mem.tracked_alloc_at(base) {
                    Some((alloc_base, alloc_size, _)) => {
                        let Some(release_end) = base.checked_add(aligned_release_size) else {
                            return Err(NtStatus::STATUS_INVALID_PARAMETER);
                        };
                        let Some(alloc_end) = alloc_base.checked_add(alloc_size) else {
                            return Err(NtStatus::STATUS_INVALID_PARAMETER);
                        };
                        if release_end > alloc_end {
                            return Err(NtStatus::STATUS_INVALID_PARAMETER);
                        }
                        Some((base, aligned_release_size))
                    }
                    None => None,
                };
                (aligned_release_size, tracked_release)
            };

            // Remove PM pages under the same lock.
            let release_end = base.saturating_add(release_size);
            let overlapping: alloc::vec::Vec<_> = vmem
                .overlapping(base..release_end)
                .map(|(range, _)| (range.start.max(base), range.end.min(release_end)))
                .filter(|(s, e)| e > s)
                .collect();
            for (start, end) in overlapping {
                if let Some(pr) = litebox::mm::linux::PageRange::<PAGE_SIZE>::new(start, end) {
                    let _ = unsafe { vmem.remove_mapping(pr) };
                }
            }

            // Update metadata.
            if let Some((release_base, release_sz)) = tracked_release {
                let _ = mem.release_tracked_alloc_range(release_base, release_sz);
            }
            mem.pm_recommit(base, release_size);
            mem.clear_guard_pages(base, release_size);
            Ok((base, release_size))
        });

        match release_result {
            Ok((release_base, released_size)) => {
                write_guest_usize(base_addr_ptr, release_base).ok();
                write_guest_usize(region_size_ptr, released_size).ok();
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtFreeVirtualMemory MEM_RELEASE base=0x{release_base:X} size=0x{released_size:X}\n",
                    ));
                }
                NtStatus::STATUS_SUCCESS
            }
            Err(status) => status,
        }
    } else if free_type & mem_alloc_type::MEM_DECOMMIT != 0 {
        // MEM_DECOMMIT: revert pages to inaccessible (reserved) state.
        // The address range stays in the VA map but becomes inaccessible.
        //
        // All operations (reservation check, page reset, permission change,
        // metadata update) are performed under a single write lock to prevent
        // races with concurrent MEM_COMMIT on the same reservation.
        let Some(decommit_size) = align_up(size, PAGE_SIZE) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };
        if decommit_size == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }
        let Some(decommit_end) = base.checked_add(decommit_size) else {
            return NtStatus::STATUS_INVALID_PARAMETER;
        };

        let result: Result<(), NtStatus> = ps.with_memory(|vmem, mem| {
            let in_va_reservation = mem.va_reservation_at(base).is_some();
            if in_va_reservation
                && mem
                    .va_reservation_contains_range(base, decommit_size)
                    .is_none()
            {
                return Err(NtStatus::STATUS_UNABLE_TO_FREE_VM);
            }

            // If the reservation has no PM-backed pages, just update metadata.
            if in_va_reservation {
                let pm_has_pages = vmem.overlapping(base..decommit_end).next().is_some();
                if !pm_has_pages {
                    mem.va_decommit(base, decommit_size);
                    mem.clear_guard_pages(base, decommit_size);
                    #[cfg(debug_assertions)]
                    {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "NT shim: NtFreeVirtualMemory MEM_DECOMMIT (VA reservation) base=0x{base:X} size=0x{decommit_size:X}\n",
                        ));
                    }
                    return Ok(());
                }
            }

            // Reset page contents (discard+recreate to zero), then make
            // inaccessible, then update metadata — all under one lock.
            // Note: reset_pages returns FileBacked if any file-backed VMA is
            // encountered. Earlier anonymous pages may already be reset in
            // that case, but this is acceptable because file-backed ranges
            // should never overlap with heap VA reservations in practice.
            if let Some(range) =
                litebox::mm::linux::PageRange::<PAGE_SIZE>::new(base, decommit_end)
            {
                match unsafe { vmem.reset_pages(range, true) } {
                    Ok(())
                    | Err(litebox::mm::linux::VmemResetError::AlreadyUnallocated) => {}
                    Err(litebox::mm::linux::VmemResetError::FileBacked) => {
                        return Err(NtStatus::STATUS_UNABLE_TO_FREE_VM);
                    }
                    Err(litebox::mm::linux::VmemResetError::UnAligned) => {
                        return Err(NtStatus::STATUS_INVALID_PARAMETER);
                    }
                }
                let protect_result = unsafe {
                    vmem.protect_mapping(range, MemoryRegionPermissions::empty())
                };
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "NT shim: NtFreeVirtualMemory MEM_DECOMMIT base=0x{base:X} size=0x{decommit_size:X} result={}\n",
                        if protect_result.is_ok() { "OK" } else { "FAILED" }
                    ));
                }
                if protect_result.is_err() {
                    return Err(NtStatus::STATUS_MEMORY_NOT_ALLOCATED);
                }
            }

            if in_va_reservation {
                mem.va_decommit(base, decommit_size);
            } else {
                mem.pm_decommit(base, decommit_size);
            }
            mem.clear_guard_pages(base, decommit_size);
            Ok(())
        });

        match result {
            Ok(()) => {
                write_guest_usize(base_addr_ptr, base).ok();
                write_guest_usize(region_size_ptr, decommit_size).ok();
                NtStatus::STATUS_SUCCESS
            }
            Err(status) => status,
        }
    } else {
        NtStatus::STATUS_INVALID_PARAMETER
    }
}

/// NtProtectVirtualMemory — change page protection.
///
/// NT signature:
/// ```text
/// NTSTATUS NtProtectVirtualMemory(
///     HANDLE ProcessHandle,      // r10
///     PVOID *BaseAddress,        // rdx (in/out)
///     PSIZE_T RegionSize,        // r8 (in/out)
///     ULONG NewProtect,          // r9
///     PULONG OldProtect          // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_protect_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);

    let base_addr_ptr = args.arg1;
    let region_size_ptr = args.arg2;
    let new_protect = args.arg3 as u32;

    if base_addr_ptr == 0 || region_size_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    let base = match read_guest_usize(base_addr_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };
    let size = match read_guest_usize(region_size_ptr) {
        Ok(v) => v,
        Err(s) => return s,
    };

    // Read OldProtect pointer from stack.
    let old_protect_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);

    let aligned_base = base & !(PAGE_SIZE - 1);
    let end = base.saturating_add(size);
    let aligned_size = (end
        .saturating_sub(aligned_base)
        .saturating_add(PAGE_SIZE - 1))
        & !(PAGE_SIZE - 1);

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtProtectVirtualMemory: base=0x{base:X} size=0x{size:X} new_protect=0x{new_protect:X} aligned=0x{aligned_base:X}+0x{aligned_size:X}\n"
            ),
        );
    }

    if aligned_size == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Determine the actual current protection before we change anything so
    // we can return it through OldProtect.  First check PM (page manager)
    // mappings, then fall back to VA reservation bookkeeping, and finally
    // default to PAGE_NOACCESS for reserved-but-not-committed pages.
    let actual_old_protect = ps.with_memory_read(|vmem, mem| {
        if let Some(&base_prot) = mem.guard_pages.get(&(aligned_base & !(PAGE_SIZE - 1))) {
            base_prot | 0x100
        } else {
            let mut found_protect = None;
            for (range, vma) in vmem.iter() {
                if aligned_base >= range.start && aligned_base < range.end {
                    let perms = MemoryRegionPermissions::from(vma.flags());
                    if perms.is_empty() {
                        found_protect = Some(mem_protect::PAGE_NOACCESS);
                    } else {
                        found_protect = Some(region_perms_to_nt_protect(perms));
                    }
                    break;
                }
            }
            found_protect
                .or_else(|| mem.va_committed_protect(aligned_base))
                .unwrap_or(mem_protect::PAGE_NOACCESS)
        }
    });
    if old_protect_ptr != 0
        && !crate::try_write_guest_value_unaligned::<u32>(old_protect_ptr, actual_old_protect)
    {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let has_guard = (new_protect & 0x100) != 0;
    let base_protect = new_protect & 0xFF;
    if has_guard {
        let guard_result = ps.with_memory(|vmem, mem| {
            let inaccessible = MemoryRegionPermissions::empty();
            // Image mappings take priority over VA reservations.
            if let Some((img_base, img_size)) = ps.image_mapping_at(aligned_base) {
                let Some(guard_end) = aligned_base.checked_add(aligned_size) else {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                };
                let Some(img_end) = img_base.checked_add(img_size) else {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                };
                if guard_end > img_end {
                    return Err(NtStatus(0xC000_0141u32 as i32));
                }
                protect_overlapping_pm_subranges(
                    vmem,
                    aligned_base,
                    aligned_size,
                    inaccessible,
                    false,
                )?;
                mem.pm_recommit(aligned_base, aligned_size);
                mem.set_guard_pages(aligned_base, aligned_size, base_protect);
                return Ok(());
            }
            let in_reservation = mem
                .va_reservation_contains_range(aligned_base, aligned_size)
                .is_some();
            if in_reservation && mem.va_committed_fully(aligned_base, aligned_size) {
                protect_overlapping_pm_subranges(
                    vmem,
                    aligned_base,
                    aligned_size,
                    inaccessible,
                    false,
                )?;
                mem.set_guard_pages(aligned_base, aligned_size, base_protect);
                mem.va_commit(aligned_base, aligned_size, new_protect);
                return Ok(());
            }
            if in_reservation {
                // Partially-committed VA reservation: protect and guard
                // only committed sub-ranges, skip decommitted gaps.
                // Two-phase: apply all PM changes first, then metadata.
                let Some(commit_end) = aligned_base.checked_add(aligned_size) else {
                    return Err(NtStatus::STATUS_INVALID_PARAMETER);
                };
                // Phase 1: collect committed pages and apply PM protection.
                let mut applied: alloc::vec::Vec<(
                    usize,
                    litebox::platform::page_mgmt::MemoryRegionPermissions,
                )> = alloc::vec::Vec::new();
                let mut page = aligned_base;
                while page < commit_end {
                    if mem.va_committed_protect(page).is_some() {
                        if let Some(pr) =
                            litebox::mm::linux::PageRange::<PAGE_SIZE>::new(page, page + PAGE_SIZE)
                        {
                            if let Some(old_perms) = vmem.get_memory_permissions(pr) {
                                if unsafe { vmem.protect_mapping(pr, inaccessible) }.is_err() {
                                    // Rollback already-applied pages.
                                    for &(rb_page, rb_perms) in applied.iter().rev() {
                                        if let Some(rb_pr) = litebox::mm::linux::PageRange::<
                                            PAGE_SIZE,
                                        >::new(
                                            rb_page, rb_page + PAGE_SIZE
                                        ) {
                                            let _ =
                                                unsafe { vmem.protect_mapping(rb_pr, rb_perms) };
                                        }
                                    }
                                    return Err(NtStatus::STATUS_INVALID_PAGE_PROTECTION);
                                }
                                applied.push((page, old_perms));
                            } else {
                                // Not yet materialized — will be guarded on demand-fault.
                                applied.push((
                                    page,
                                    litebox::platform::page_mgmt::MemoryRegionPermissions::empty(),
                                ));
                            }
                        }
                    }
                    page += PAGE_SIZE;
                }
                if applied.is_empty() {
                    return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
                }
                // Phase 2: all PM changes succeeded — update metadata.
                for &(p, _) in &applied {
                    mem.guard_pages.insert(p, base_protect);
                    mem.va_commit(p, PAGE_SIZE, new_protect);
                }
                return Ok(());
            }

            if mem.pm_range_is_decommitted(aligned_base, aligned_size) {
                return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
            }
            let (alloc_base, alloc_size) =
                if let Some((ab, as_, _)) = mem.tracked_alloc_at(aligned_base) {
                    (ab, as_)
                } else if let Some((ib, is)) = ps.image_mapping_at(aligned_base) {
                    // Image-mapped pages (loaded DLLs) are not in the
                    // allocation tracker but are valid committed pages.
                    (ib, is)
                } else {
                    return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
                };
            let Some(guard_end) = aligned_base.checked_add(aligned_size) else {
                return Err(NtStatus::STATUS_INVALID_PARAMETER);
            };
            let Some(alloc_end) = alloc_base.checked_add(alloc_size) else {
                return Err(NtStatus::STATUS_INVALID_PARAMETER);
            };
            if guard_end > alloc_end {
                return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
            }

            protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, inaccessible, true)?;
            mem.pm_recommit(aligned_base, aligned_size);
            mem.set_guard_pages(aligned_base, aligned_size, base_protect);
            Ok(())
        });
        if let Err(status) = guard_result {
            return status;
        }
        // Post-operation writeback: operation already completed, guest
        // pointers were validated at entry. Ignoring write failures is
        // acceptable — matches NT ProbeForWrite semantics where the
        // kernel writes inside try/except after the operation.
        write_guest_usize(base_addr_ptr, aligned_base).ok();
        write_guest_usize(region_size_ptr, aligned_size).ok();
        return NtStatus::STATUS_SUCCESS;
    }

    // If the range is inside a VA-only reservation, update the lazy-commit
    // bookkeeping so that future demand-faults and queries reflect the new
    // protection.  Also update PM for any pages already materialised.
    //
    // All operations (reservation check, PM permission updates, metadata) are
    // performed under a single write lock to close the TOCTOU gap.
    let protect_result: Result<(), NtStatus> = ps.with_memory(|vmem, mem| {
        // Image mappings (loaded DLLs) take priority: their pages are
        // always committed and may overlap VA reservations created by the
        // loader.  Handle them directly without consulting reservation or
        // allocation bookkeeping.
        if let Some((img_base, img_size)) = ps.image_mapping_at(aligned_base) {
            let Some(protect_end) = aligned_base.checked_add(aligned_size) else {
                return Err(NtStatus::STATUS_INVALID_PARAMETER);
            };
            let Some(img_end) = img_base.checked_add(img_size) else {
                return Err(NtStatus::STATUS_INVALID_PARAMETER);
            };
            if protect_end > img_end {
                return Err(NtStatus(0xC000_0141u32 as i32)); // out of image bounds
            }
            let perms = page_op_to_permissions(nt_protect_to_page_op(new_protect));
            // Allow gaps between PE sections — not all pages may be
            // contiguously mapped in the page manager.
            protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, perms, false)?;
            mem.clear_guard_pages(aligned_base, aligned_size);
            return Ok(());
        }

        let in_reservation = mem
            .va_reservation_contains_range(aligned_base, aligned_size)
            .is_some();
        if in_reservation && mem.va_committed_fully(aligned_base, aligned_size) {
            // Update PM pages that were already demand-faulted first.  Walk
            // mapped subranges individually (unmaterialised holes are skipped).
            // Only update bookkeeping if all PM changes succeed.
            let perms = page_op_to_permissions(nt_protect_to_page_op(new_protect));
            protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, perms, false)?;
            // PM changes succeeded — now update bookkeeping.
            mem.clear_guard_pages(aligned_base, aligned_size);
            mem.va_commit(aligned_base, aligned_size, new_protect);
            return Ok(());
        }
        if in_reservation {
            // Partially-committed VA reservation: protect and update
            // only committed sub-ranges, skip decommitted gaps.
            // Two-phase: apply all PM changes first, then metadata.
            let perms = page_op_to_permissions(nt_protect_to_page_op(new_protect));
            let Some(commit_end) = aligned_base.checked_add(aligned_size) else {
                return Err(NtStatus::STATUS_INVALID_PARAMETER);
            };
            // Phase 1: collect committed pages and apply PM protection.
            let mut applied: alloc::vec::Vec<(
                usize,
                litebox::platform::page_mgmt::MemoryRegionPermissions,
            )> = alloc::vec::Vec::new();
            let mut page = aligned_base;
            while page < commit_end {
                if mem.va_committed_protect(page).is_some() {
                    if let Some(pr) =
                        litebox::mm::linux::PageRange::<PAGE_SIZE>::new(page, page + PAGE_SIZE)
                    {
                        if let Some(old_perms) = vmem.get_memory_permissions(pr) {
                            if unsafe { vmem.protect_mapping(pr, perms) }.is_err() {
                                // Rollback already-applied pages.
                                for &(rb_page, rb_perms) in applied.iter().rev() {
                                    if let Some(rb_pr) =
                                        litebox::mm::linux::PageRange::<PAGE_SIZE>::new(
                                            rb_page,
                                            rb_page + PAGE_SIZE,
                                        )
                                    {
                                        let _ = unsafe { vmem.protect_mapping(rb_pr, rb_perms) };
                                    }
                                }
                                return Err(NtStatus::STATUS_INVALID_PAGE_PROTECTION);
                            }
                            applied.push((page, old_perms));
                        } else {
                            applied.push((
                                page,
                                litebox::platform::page_mgmt::MemoryRegionPermissions::empty(),
                            ));
                        }
                    }
                }
                page += PAGE_SIZE;
            }
            if applied.is_empty() {
                return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
            }
            // Phase 2: all PM changes succeeded — update metadata.
            for &(p, _) in &applied {
                mem.guard_pages.remove(&p);
                mem.va_commit(p, PAGE_SIZE, new_protect);
            }
            return Ok(());
        }

        // Not inside a VA reservation: operate directly on PM-backed mappings.
        if mem.pm_range_is_decommitted(aligned_base, aligned_size) {
            // Real NT rejects VirtualProtect on uncommitted pages.
            return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
        }
        let is_image = ps.image_mapping_at(aligned_base);
        let (alloc_base, alloc_size) =
            if let Some((ab, as_, _)) = mem.tracked_alloc_at(aligned_base) {
                (ab, as_)
            } else if let Some((ib, is)) = is_image {
                // Image-mapped pages (loaded DLLs) are not in the
                // allocation tracker but are valid committed pages.
                (ib, is)
            } else {
                return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
            };
        let Some(protect_end) = aligned_base.checked_add(aligned_size) else {
            return Err(NtStatus::STATUS_INVALID_PARAMETER);
        };
        let Some(alloc_end) = alloc_base.checked_add(alloc_size) else {
            return Err(NtStatus::STATUS_INVALID_PARAMETER);
        };
        if protect_end > alloc_end {
            return Err(NtStatus(0xC000_0141u32 as i32)); // STATUS_NOT_COMMITTED
        }
        // For image mappings, allow gaps between PE sections — not all
        // pages may be contiguously mapped.
        let full_coverage = is_image.is_none();
        let perms = page_op_to_permissions(nt_protect_to_page_op(new_protect));
        protect_overlapping_pm_subranges(vmem, aligned_base, aligned_size, perms, full_coverage)?;
        mem.pm_recommit(aligned_base, aligned_size);
        mem.clear_guard_pages(aligned_base, aligned_size);
        Ok(())
    });
    match protect_result {
        Ok(()) => {
            write_guest_usize(base_addr_ptr, aligned_base).ok();
            write_guest_usize(region_size_ptr, aligned_size).ok();
            NtStatus::STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// NtQueryVirtualMemory — query information about a memory region.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryVirtualMemory(
///     HANDLE ProcessHandle,              // r10
///     PVOID BaseAddress,                 // rdx
///     MEMORY_INFORMATION_CLASS MemClass,  // r8
///     PVOID MemoryInformation,           // r9
///     SIZE_T MemoryInformationLength,    // [rsp+0x28]
///     PSIZE_T ReturnLength               // [rsp+0x30]
/// );
/// ```
pub(crate) fn nt_query_virtual_memory(
    ctx: &mut super::super::ExecutionContext,
    ps: &super::super::NtProcessState,
    module_bases: &[super::super::ModuleBase],
) -> NtStatus {
    use litebox_common_windows::nt_types::MemoryBasicInformation;

    let pm = &ps.pm;
    let args = NtSyscallArgs::from_ctx(ctx);
    let query_addr = args.arg1;
    let info_class = args.arg2 as u32;
    let info_ptr = args.arg3;

    let info_length =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x28).unwrap_or(0);
    let return_length_ptr =
        crate::try_read_guest_value_unaligned::<usize>(ctx.regs.rsp + 0x30).unwrap_or(0);

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtQueryVirtualMemory: addr=0x{query_addr:X} class={info_class} buf=0x{info_ptr:X} len={info_length}\n",
            ),
        );
    }

    // Class 6: MemoryImageInformation — return PE image base/size for an address.
    if info_class == 6 {
        // MEMORY_IMAGE_INFORMATION: { ImageBase: PVOID, SizeOfImage: SIZE_T, ImageFlags: ULONG }
        const MEMORY_IMAGE_INFORMATION_SIZE: usize = 24;
        const MEMORY_IMAGE_FLAGS_MAPPED_IMAGE: u32 = 0x70;

        if info_ptr == 0 {
            return NtStatus::STATUS_INVALID_PARAMETER;
        }

        if info_length < MEMORY_IMAGE_INFORMATION_SIZE {
            return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
        }

        let write_memory_image_information =
            |image_base: usize, size_of_image: usize, flags: u32| {
                crate::try_write_guest_value_unaligned::<u64>(info_ptr, image_base as u64);
                crate::try_write_guest_value_unaligned::<u64>(info_ptr + 8, size_of_image as u64);
                crate::try_write_guest_value_unaligned::<u32>(info_ptr + 16, flags);
                crate::try_write_guest_value_unaligned::<u32>(info_ptr + 20, 0u32);
                if return_length_ptr != 0 {
                    crate::try_write_guest_value_unaligned::<usize>(
                        return_length_ptr,
                        MEMORY_IMAGE_INFORMATION_SIZE,
                    );
                }
            };

        // Find the module containing this address — check both runner-loaded
        // modules and dynamically mapped images (via NtMapViewOfSection).
        let module = module_bases
            .iter()
            .find(|m| query_addr >= m.base_address && query_addr < m.base_address + m.image_size);
        if let Some(m) = module {
            write_memory_image_information(
                m.base_address,
                m.image_size,
                MEMORY_IMAGE_FLAGS_MAPPED_IMAGE,
            );
            return NtStatus::STATUS_SUCCESS;
        }
        // Check dynamically loaded images (SEC_IMAGE via NtMapViewOfSection).
        {
            let img_mappings = ps.image_mappings.lock();
            if let Some((&base, &size)) = img_mappings
                .range(..=query_addr)
                .next_back()
                .filter(|&(&b, &s)| query_addr < b + s)
            {
                write_memory_image_information(base, size, MEMORY_IMAGE_FLAGS_MAPPED_IMAGE);
                return NtStatus::STATUS_SUCCESS;
            }
        }

        // Windows returns STATUS_SUCCESS with zeroed MEMORY_IMAGE_INFORMATION
        // for valid non-image mappings (including MEM_PRIVATE and pure
        // reservations). Only truly unmapped addresses return
        // STATUS_INVALID_ADDRESS.
        let aligned_addr = query_addr & !(crate::PAGE_SIZE - 1);
        let in_non_image_mapping = pm
            .mappings()
            .iter()
            .any(|(range, _)| aligned_addr >= range.start && aligned_addr < range.end)
            || ps.with_memory_read(|_vmem, mem| mem.va_reservation_at(aligned_addr).is_some());
        if in_non_image_mapping {
            write_memory_image_information(0, 0, 0);
            return NtStatus::STATUS_SUCCESS;
        }

        return NtStatus::STATUS_INVALID_ADDRESS;
    }

    // Class 4: MemoryWorkingSetExInformation — return zeroed data (no working set info in sandbox).
    if info_class == 4 {
        if info_ptr != 0 && info_length > 0 {
            let write_len = core::cmp::min(info_length, 0x10000);
            if !crate::is_addr_range_writable(info_ptr, write_len) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, write_len);
            }
        }
        if return_length_ptr != 0 {
            crate::try_write_guest_value_unaligned::<usize>(return_length_ptr, info_length);
        }
        return NtStatus::STATUS_SUCCESS;
    }

    // Only MemoryBasicInformation (class 0) is supported beyond this point.
    // Class 14 = MemoryImageExtensionInformation — used by the loader for
    // image integrity checks. Return success with zeroed data to indicate
    // no extension info is available.
    if info_class == 14 {
        if info_ptr != 0 {
            let write_len = info_length.min(64);
            if !crate::is_addr_range_writable(info_ptr, write_len) {
                return NtStatus::STATUS_ACCESS_VIOLATION;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, write_len);
            }
        }
        if return_length_ptr != 0 {
            crate::try_write_guest_value_unaligned::<usize>(return_length_ptr, info_length);
        }
        return NtStatus::STATUS_SUCCESS;
    }
    if info_class != 0 {
        return NtStatus::STATUS_INVALID_INFO_CLASS;
    }

    let mbi_size = core::mem::size_of::<MemoryBasicInformation>();
    if info_length < mbi_size || info_ptr == 0 {
        return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
    }

    // Query PageManager for the memory region containing this address.
    let aligned_addr = query_addr & !(PAGE_SIZE - 1);

    // Walk the VMAs and NtMemoryState inside with_memory_read to find the
    // region, its permissions, tracked allocation info, and VA reservations.
    let (state, protect, allocation_protect, mut alloc_base, region_size) =
        ps.with_memory_read(|vmem, mem| {
            let mut state = mem_state::MEM_FREE;
            let mut protect = 0u32;
            let mut allocation_protect = 0u32;
            let mut alloc_base = aligned_addr;
            let mut region_size = PAGE_SIZE;

            // Find the VMA containing aligned_addr.
            let mut found = false;
            for (range, vma) in vmem.iter() {
                if aligned_addr >= range.start && aligned_addr < range.end {
                    let perms = MemoryRegionPermissions::from(vma.flags());
                    if perms.is_empty() {
                        // Empty perms in PM can mean:
                        // 1. Guard page (committed but made inaccessible) → MEM_COMMIT
                        // 2. Committed PAGE_NOACCESS → MEM_COMMIT
                        // 3. Decommitted page (PM mapping remains) → MEM_RESERVE
                        let is_committed_noaccess =
                            mem.va_committed_protect(aligned_addr).is_some()
                                || (mem.tracked_alloc_at(aligned_addr).is_some()
                                    && !mem.pm_is_decommitted(aligned_addr));
                        if let Some(&base_prot) =
                            mem.guard_pages.get(&(aligned_addr & !(PAGE_SIZE - 1)))
                        {
                            state = mem_state::MEM_COMMIT;
                            protect = base_prot | 0x100; // PAGE_GUARD
                        } else if is_committed_noaccess {
                            state = mem_state::MEM_COMMIT;
                            protect = mem_protect::PAGE_NOACCESS;
                        } else {
                            // Decommitted — still has PM mapping but no committed entry.
                            state = mem_state::MEM_RESERVE;
                            protect = 0;
                        }
                    } else {
                        state = mem_state::MEM_COMMIT;
                        protect = region_perms_to_nt_protect(perms);
                        if mem.is_guard_page(aligned_addr) {
                            protect |= 0x100;
                        }
                    }
                    alloc_base = range.start;
                    region_size = range.end - aligned_addr;
                    if let Some((tracked_base, tracked_size, tracked_protect)) =
                        mem.tracked_alloc_at(aligned_addr)
                    {
                        let tracked_end = tracked_base.saturating_add(tracked_size);
                        alloc_base = tracked_base;
                        allocation_protect = tracked_protect;
                        region_size = region_size.min(tracked_end.saturating_sub(aligned_addr));
                    } else {
                        allocation_protect = protect;
                    }
                    found = true;
                    break;
                }
            }

            // If not found in PM, also check module_bases for raw-mapped DLLs.
            if !found {
                for m in module_bases {
                    if aligned_addr >= m.base_address
                        && aligned_addr < m.base_address + m.image_size
                    {
                        state = mem_state::MEM_COMMIT;
                        protect = mem_protect::PAGE_READONLY;
                        allocation_protect = mem_protect::PAGE_READONLY;
                        alloc_base = m.base_address;
                        region_size = m.base_address + m.image_size - aligned_addr;
                        found = true;
                        break;
                    }
                }
            }

            // If not found in PM, check VA-only reservations (MEM_RESERVE without
            // MEM_COMMIT). These are pure bookkeeping entries with no host pages.
            if !found {
                if let Some((res_base, res_size)) = mem.va_reservation_at(aligned_addr) {
                    // Check if this page was explicitly committed (lazy).
                    if let Some(prot) = mem.va_committed_protect(aligned_addr) {
                        state = mem_state::MEM_COMMIT;
                        protect = prot;
                    } else {
                        state = mem_state::MEM_RESERVE;
                        protect = 0; // reserved but not committed → no page protection
                    }
                    allocation_protect =
                        litebox_common_windows::nt_types::mem_protect::PAGE_READWRITE;
                    alloc_base = res_base;
                    // Region size extends to the next state/protection boundary,
                    // not the entire reservation.
                    region_size = mem.va_region_size_at(aligned_addr, res_base, res_size);
                    found = true;
                }
            }

            // If still not found, report as free memory.  Compute region_size as the
            // gap to the next mapped region (or a default 64 KiB).
            if !found {
                state = mem_state::MEM_FREE;
                protect = 0;
                allocation_protect = 0;
                alloc_base = aligned_addr;
                region_size = 0x10000; // default gap size
                for (range, _) in vmem.iter() {
                    if range.start > aligned_addr {
                        region_size = range.start - aligned_addr;
                        break;
                    }
                }
            }

            (state, protect, allocation_protect, alloc_base, region_size)
        });

    // Determine the memory type. Image-mapped DLLs report MEM_IMAGE;
    // regular allocations report MEM_PRIVATE. For image regions, also
    // correct the allocation base to the image base.
    let mem_type = if state != mem_state::MEM_FREE {
        // Check SEC_IMAGE mappings (dynamically loaded via NtMapViewOfSection).
        let img_mappings = ps.image_mappings.lock();
        let dyn_img = img_mappings
            .range(..=aligned_addr)
            .next_back()
            .filter(|&(&base, &size)| aligned_addr < base + size);

        // Check runner-loaded modules (ntdll, EXE).
        let runner_img = module_bases.iter().find(|m| {
            aligned_addr >= m.base_address && aligned_addr < m.base_address + m.image_size
        });

        if let Some((&base, _)) = dyn_img {
            alloc_base = base;
            0x0100_0000 // MEM_IMAGE
        } else if let Some(m) = runner_img {
            alloc_base = m.base_address;
            0x0100_0000 // MEM_IMAGE
        } else {
            0x0002_0000 // MEM_PRIVATE
        }
    } else {
        0
    };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        let type_str = match mem_type {
            0x0100_0000 => "MEM_IMAGE",
            0x0002_0000 => "MEM_PRIVATE",
            _ => "MEM_FREE",
        };
        litebox_platform_multiplex::platform().debug_log_print(
            &alloc::format!(
                "  NtQueryVirtualMemory: addr=0x{aligned_addr:X} → state=0x{state:X} protect=0x{protect:X} alloc_base=0x{alloc_base:X} region_size=0x{region_size:X} type={type_str}\n",
            ),
        );
    }

    let mbi = MemoryBasicInformation {
        base_address: aligned_addr as u64,
        allocation_base: alloc_base as u64,
        allocation_protect: allocation_protect,
        _pad0: 0,
        region_size: region_size as u64,
        state,
        protect,
        type_: mem_type,
        _pad1: 0,
    };

    crate::try_write_guest_value_unaligned::<MemoryBasicInformation>(info_ptr, mbi);

    if return_length_ptr != 0 {
        crate::try_write_guest_value_unaligned::<usize>(return_length_ptr, mbi_size);
    }

    NtStatus::STATUS_SUCCESS
}

/// Internal page operation categories.
#[derive(Clone, Copy)]
pub(crate) enum PageOp {
    NoAccess,
    ReadOnly,
    ReadWrite,
    WriteCopy,
    Execute,
    ExecuteRead,
    ExecuteReadWrite,
}

/// Map NT PAGE_* protection to our internal operation category.
fn nt_protect_to_page_op(protect: u32) -> PageOp {
    // Strip modifier flags (PAGE_GUARD, PAGE_NOCACHE, etc.)
    let base = protect & 0xFF;
    match base {
        mem_protect::PAGE_NOACCESS => PageOp::NoAccess,
        mem_protect::PAGE_READONLY => PageOp::ReadOnly,
        mem_protect::PAGE_READWRITE => PageOp::ReadWrite,
        mem_protect::PAGE_WRITECOPY => PageOp::WriteCopy,
        mem_protect::PAGE_EXECUTE => PageOp::Execute,
        mem_protect::PAGE_EXECUTE_READ => PageOp::ExecuteRead,
        mem_protect::PAGE_EXECUTE_READWRITE => PageOp::ExecuteReadWrite,
        // Default to RW for unknown protection values.
        _ => PageOp::ReadWrite,
    }
}

/// Convert a [`PageOp`] to [`MemoryRegionPermissions`] for use with `Vmem`
/// methods (`create_pages`, `protect_mapping`).
fn page_op_to_permissions(op: PageOp) -> MemoryRegionPermissions {
    match op {
        PageOp::NoAccess => MemoryRegionPermissions::empty(),
        PageOp::ReadOnly => MemoryRegionPermissions::READ,
        PageOp::ReadWrite | PageOp::WriteCopy => {
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE
        }
        PageOp::Execute => MemoryRegionPermissions::EXEC,
        PageOp::ExecuteRead => MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        PageOp::ExecuteReadWrite => {
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC
        }
    }
}

/// Map litebox `MemoryRegionPermissions` to NT PAGE_* protection constants.
fn region_perms_to_nt_protect(perms: MemoryRegionPermissions) -> u32 {
    region_perms_to_nt_protect_pub(perms)
}

/// Public version of `nt_protect_to_page_op` for use by k32_handlers.
pub(crate) fn nt_protect_to_page_op_pub(protect: u32) -> PageOp {
    nt_protect_to_page_op(protect)
}

/// Public version of `region_perms_to_nt_protect` for use by k32_handlers.
pub(crate) fn region_perms_to_nt_protect_pub(perms: MemoryRegionPermissions) -> u32 {
    let r = perms.contains(MemoryRegionPermissions::READ);
    let w = perms.contains(MemoryRegionPermissions::WRITE);
    let x = perms.contains(MemoryRegionPermissions::EXEC);
    match (r, w, x) {
        (false, false, false) => mem_protect::PAGE_NOACCESS,
        (true, false, false) => mem_protect::PAGE_READONLY,
        (true, true, false) => mem_protect::PAGE_READWRITE,
        (true, false, true) => mem_protect::PAGE_EXECUTE_READ,
        (true, true, true) => mem_protect::PAGE_EXECUTE_READWRITE,
        (false, false, true) => mem_protect::PAGE_EXECUTE,
        _ => mem_protect::PAGE_READWRITE,
    }
}
