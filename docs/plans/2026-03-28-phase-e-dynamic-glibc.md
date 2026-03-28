# Phase E: Dynamic glibc Hello World Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Run a dynamically-linked glibc `puts("Hello World")` program through the litebox_launcher end-to-end.

**Architecture:** Fix 5 blockers that prevent dynamic glibc binaries from working: (1) make GuestMutPtr/GuestConstPtr dereference real memory in central's address space, (2) add dual-dispatch for memory management syscalls so micro creates real mappings, (3) transfer file-backed mmap data through the shared memory data region, (4) add a tar_ro filesystem layer for shared libraries, (5) initialize brk from the ELF loader. Additionally, add missing syscalls to `needs_local_exec` and expand micro's local execution to handle the full dynamic linker syscall sequence.

**Tech Stack:** Rust, libc, shared-memory IPC ring buffer, `tar_ro` filesystem, ELF loading

---

## Task 1: Fix GuestConstPtr and GuestMutPtr to dereference real memory

Central's `allocate_pages` maps real memory in its own address space via `libc::mmap`, so the addresses stored in `GuestMutPtr`/`GuestConstPtr` are valid pointers in central's process. Implement the 6 stubbed methods as raw pointer dereferences.

**Files:**
- Modify: `litebox_platform_central/src/lib.rs:247-322`
- Test: `litebox_platform_central/src/lib.rs` (inline tests)

**Step 1: Write tests for GuestConstPtr and GuestMutPtr dereference**

Add a test module at the end of `litebox_platform_central/src/lib.rs`:

```rust
#[cfg(test)]
mod guest_ptr_tests {
    use super::*;
    use litebox::platform::{RawConstPointer, RawMutPointer};

    #[test]
    fn guest_const_ptr_read_at_offset() {
        let values: [u64; 3] = [42, 99, 7];
        let ptr = GuestConstPtr::<u64>::from_usize(values.as_ptr() as usize);
        assert_eq!(ptr.read_at_offset(0), Some(42));
        assert_eq!(ptr.read_at_offset(1), Some(99));
        assert_eq!(ptr.read_at_offset(2), Some(7));
    }

    #[test]
    fn guest_const_ptr_to_owned_slice() {
        let values: [u32; 4] = [1, 2, 3, 4];
        let ptr = GuestConstPtr::<u32>::from_usize(values.as_ptr() as usize);
        let slice = ptr.to_owned_slice(4).unwrap();
        assert_eq!(&*slice, &[1, 2, 3, 4]);
    }

    #[test]
    fn guest_const_ptr_null_returns_none() {
        let ptr = GuestConstPtr::<u64>::from_usize(0);
        assert_eq!(ptr.read_at_offset(0), None);
        assert!(ptr.to_owned_slice(1).is_none());
    }

    #[test]
    fn guest_mut_ptr_read_at_offset() {
        let mut values: [u64; 2] = [10, 20];
        let ptr = GuestMutPtr::<u64>::from_usize(values.as_mut_ptr() as usize);
        assert_eq!(RawConstPointer::read_at_offset(ptr, 0), Some(10));
        assert_eq!(RawConstPointer::read_at_offset(ptr, 1), Some(20));
    }

    #[test]
    fn guest_mut_ptr_to_owned_slice() {
        let mut values: [u8; 3] = [0xAA, 0xBB, 0xCC];
        let ptr = GuestMutPtr::<u8>::from_usize(values.as_mut_ptr() as usize);
        let slice = RawConstPointer::to_owned_slice(ptr, 3).unwrap();
        assert_eq!(&*slice, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn guest_mut_ptr_write_at_offset() {
        let mut values: [u64; 2] = [0, 0];
        let ptr = GuestMutPtr::<u64>::from_usize(values.as_mut_ptr() as usize);
        assert_eq!(ptr.write_at_offset(0, 42), Some(()));
        assert_eq!(ptr.write_at_offset(1, 99), Some(()));
        assert_eq!(values, [42, 99]);
    }

    #[test]
    fn guest_mut_ptr_mutate_subslice_with() {
        let mut values: [u8; 4] = [0; 4];
        let ptr = GuestMutPtr::<u8>::from_usize(values.as_mut_ptr() as usize);
        let result = ptr.mutate_subslice_with(1..3, |slice| {
            slice[0] = 0xAA;
            slice[1] = 0xBB;
            42
        });
        assert_eq!(result, Some(42));
        assert_eq!(values, [0, 0xAA, 0xBB, 0]);
    }

    #[test]
    fn guest_mut_ptr_null_returns_none() {
        let ptr = GuestMutPtr::<u64>::from_usize(0);
        assert_eq!(ptr.write_at_offset(0, 42), None);
        assert_eq!(ptr.mutate_subslice_with(0..1, |_| 0), None);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p litebox_platform_central`
Expected: All `guest_ptr_tests` panic with "unimplemented!"

**Step 3: Implement GuestConstPtr methods**

Replace the two `unimplemented!()` methods in `impl<T: FromBytes> RawConstPointer<T> for GuestConstPtr<T>` (lines 247-257):

```rust
    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        // SAFETY: Central's `allocate_pages` maps real memory in this process,
        // so addresses returned by PageManager are valid pointers. Callers
        // passing guest-only addresses (e.g. stack pointers) will segfault —
        // those syscalls must be routed through `needs_local_exec` instead.
        unsafe {
            let ptr = (self.addr as *const T).offset(count);
            Some(ptr.read_unaligned())
        }
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 {
            return None;
        }
        let mut v = alloc::vec::Vec::with_capacity(len);
        unsafe {
            let src = self.addr as *const T;
            for i in 0..len {
                v.push(src.add(i).read_unaligned());
            }
        }
        Some(v.into_boxed_slice())
    }
```

**Step 4: Implement GuestMutPtr RawConstPointer methods**

Replace the two `unimplemented!()` methods in `impl<T: FromBytes> RawConstPointer<T> for GuestMutPtr<T>` (lines 296-306):

```rust
    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        unsafe {
            let ptr = (self.addr as *const T).offset(count);
            Some(ptr.read_unaligned())
        }
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 {
            return None;
        }
        let mut v = alloc::vec::Vec::with_capacity(len);
        unsafe {
            let src = self.addr as *const T;
            for i in 0..len {
                v.push(src.add(i).read_unaligned());
            }
        }
        Some(v.into_boxed_slice())
    }
```

**Step 5: Implement GuestMutPtr RawMutPointer methods**

Replace the two `unimplemented!()` methods in `impl<T: FromBytes + IntoBytes> RawMutPointer<T> for GuestMutPtr<T>` (lines 309-322):

```rust
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        if self.addr == 0 {
            return None;
        }
        unsafe {
            let ptr = (self.addr as *mut T).offset(count);
            ptr.write_unaligned(value);
        }
        Some(())
    }

    fn mutate_subslice_with<R>(
        self,
        range: impl RangeBounds<isize>,
        f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        if self.addr == 0 {
            return None;
        }
        let start = match range.start_bound() {
            core::ops::Bound::Included(&s) => s,
            core::ops::Bound::Excluded(&s) => s + 1,
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&e) => e + 1,
            core::ops::Bound::Excluded(&e) => e,
            core::ops::Bound::Unbounded => {
                // Unbounded end requires knowing total length — return None.
                return None;
            }
        };
        let len = (end - start) as usize;
        unsafe {
            let ptr = (self.addr as *mut T).offset(start);
            let slice = core::slice::from_raw_parts_mut(ptr, len);
            Some(f(slice))
        }
    }
```

**Step 6: Run tests to verify they pass**

Run: `cargo nextest run -p litebox_platform_central`
Expected: All tests pass.

**Step 7: Commit**

```
git add litebox_platform_central/src/lib.rs
git commit -m "feat(central-platform): implement GuestConstPtr/GuestMutPtr dereference

Central's allocate_pages maps real memory in the host process, so
the addresses in GuestMutPtr/GuestConstPtr are valid pointers.
Implement read_at_offset, to_owned_slice, write_at_offset, and
mutate_subslice_with as raw pointer operations. Null pointers
return None."
```

---

## Task 2: Add `data_region_mut()` to SharedRegion

Central needs mutable access to the data region to copy file-backed mmap content.

**Files:**
- Modify: `litebox_central/src/shmem.rs:246-254`
- Test: `litebox_central/src/shmem.rs` (inline test)

**Step 1: Write a test**

Add to the existing `tests` module in `shmem.rs`:

```rust
    #[test]
    fn data_region_mut_is_writable() {
        let region = SharedRegion::new().expect("failed to create shared region");
        let data = region.data_region_mut();
        assert!(!data.is_empty());
        data[0] = 0xAB;
        assert_eq!(region.data_region()[0], 0xAB);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo nextest run -p litebox_central`
Expected: FAIL — `data_region_mut` method not found.

**Step 3: Implement `data_region_mut`**

Add after the existing `data_region()` method (after line 254):

```rust
    /// Returns the data region as a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure no other references to the data region exist
    /// simultaneously. In practice, the server is single-threaded and only
    /// accesses the data region during syscall handling (between CQ writes).
    pub fn data_region_mut(&self) -> &mut [u8] {
        unsafe {
            let base = self.ptr.as_ptr().add(self.layout.data_region_offset);
            std::slice::from_raw_parts_mut(base, self.layout.data_region_size)
        }
    }
```

**Step 4: Run tests**

Run: `cargo nextest run -p litebox_central`
Expected: All tests pass.

**Step 5: Commit**

```
git add litebox_central/src/shmem.rs
git commit -m "feat(central): add data_region_mut() to SharedRegion"
```

---

## Task 3: Add dual-dispatch for mmap/munmap/mprotect/mremap/brk in central server

All memory management syscalls need to go through the shim (for PageManager state tracking) AND return `EXEC_LOCAL` so micro creates the real mapping in the guest's address space. For file-backed mmap, central also copies the populated data into the shared data region and sets `HAS_DATA`.

**Files:**
- Modify: `litebox_central/src/server.rs:192-250` (handle_syscall method)
- Test: Manual verification via integration test in Task 9

**Step 1: Modify `handle_syscall` for memory management dual-dispatch**

In `litebox_central/src/server.rs`, the default path at lines 247-249 currently dispatches all non-special syscalls through the shim and returns the result directly. We need to intercept memory management syscalls to add `EXEC_LOCAL` (and `HAS_DATA` for file-backed mmap).

Insert between the `needs_local_exec` check (line 242) and the TODO comment (line 244):

```rust
        // Memory management: dispatch through shim (PageManager state) AND
        // return EXEC_LOCAL so micro creates the real mapping.
        #[allow(clippy::cast_possible_truncation)]
        if Self::is_mm_syscall(nr) {
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if cq.result < 0 {
                // Shim returned an error — pass it through without EXEC_LOCAL.
                return cq;
            }
            cq.flags = cq_flags::EXEC_LOCAL;

            // For file-backed mmap: copy the populated data into the data region.
            if nr == libc::SYS_mmap as u32 {
                let flags = entry.args[3] as i32;
                if flags & libc::MAP_ANONYMOUS == 0 {
                    // File-backed mmap: shim populated memory at cq.result.
                    let addr = cq.result as usize;
                    let len = entry.args[1] as usize;
                    let data_region = self.region.data_region_mut();
                    let copy_len = len.min(data_region.len());
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            addr as *const u8,
                            data_region.as_mut_ptr(),
                            copy_len,
                        );
                    }
                    cq.flags |= cq_flags::HAS_DATA;
                    cq.data_offset = 0;
                    cq.data_len = copy_len as u32;
                }
            }
            return cq;
        }
```

**Step 2: Add `is_mm_syscall` helper**

Add below `needs_local_exec` (after line 355):

```rust
    /// Returns `true` for memory management syscalls that need dual-dispatch:
    /// dispatch through the shim for PageManager tracking, then EXEC_LOCAL
    /// for micro to create the real mapping.
    fn is_mm_syscall(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            libc::SYS_mmap
                | libc::SYS_munmap
                | libc::SYS_mprotect
                | libc::SYS_mremap
                | libc::SYS_madvise
                | libc::SYS_brk
        )
    }
```

**Step 3: Run clippy and build**

Run: `cargo clippy -p litebox_central`
Expected: Clean build.

**Step 4: Commit**

```
git add litebox_central/src/server.rs
git commit -m "feat(central): add dual-dispatch for memory management syscalls

mmap/munmap/mprotect/mremap/madvise/brk are dispatched through the
shim (for PageManager state tracking) and then return EXEC_LOCAL so
micro creates the real mapping. For file-backed mmap, the populated
data is copied into the shared data region with HAS_DATA flag."
```

---

## Task 4: Update micro's local execution for file-backed mmap with HAS_DATA

When micro receives a mmap CqEntry with `HAS_DATA`, it must:
1. Create an anonymous mapping at the address central chose (via `MAP_FIXED`)
2. Copy the file content from the shared data region
3. Set final permissions via `mprotect`

Also, for non-HAS_DATA mmap, micro must use `MAP_FIXED` at the address central chose (returned in `cq.result`) instead of passing through the guest's original args.

**Files:**
- Modify: `litebox_micro/src/local_exec.rs:19-31` (mmap handler)
- Modify: `litebox_micro/src/handler.rs:155` (pass ring_base and layout to execute_locally)
- Modify: `litebox_micro/src/local_exec.rs:19` (update signature to accept ring context)
- Test: `litebox_micro/src/local_exec.rs` (inline tests)

**Step 1: Update `execute_locally` signature to accept ring base and layout**

Change the function signature in `litebox_micro/src/local_exec.rs:19`:

```rust
pub unsafe fn execute_locally(
    syscall_nr: u32,
    args: &[u64; 6],
    cq: &CqEntry,
    ring_base: *mut u8,
    layout: &litebox_ipc::ring::SharedRingLayout,
) -> i64 {
```

**Step 2: Rewrite the mmap handler for dual-dispatch**

Replace the mmap arm (lines 21-31):

```rust
        nr if nr == libc::SYS_mmap as u32 => {
            if cq.flags & litebox_ipc::ring::cq_flags::HAS_DATA != 0 {
                // File-backed mmap: central populated the data in the shmem data region.
                let map_addr = cq.result as usize;
                let map_len = args[1] as usize;
                let final_prot = args[2] as i32;
                let data_len = cq.data_len as usize;

                // 1. Create anonymous mapping at the address central chose.
                let ptr = unsafe {
                    libc::mmap(
                        map_addr as *mut libc::c_void,
                        map_len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                        -1,
                        0,
                    )
                };
                if ptr == libc::MAP_FAILED {
                    return -i64::from(libc::ENOMEM);
                }

                // 2. Copy data from the shared data region.
                unsafe {
                    let data_src = ring_base
                        .add(layout.data_region_offset)
                        .add(cq.data_offset as usize);
                    core::ptr::copy_nonoverlapping(data_src, ptr.cast::<u8>(), data_len);
                }

                // 3. Set final permissions (skip if already RW).
                if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
                    unsafe { libc::mprotect(ptr, map_len, final_prot) };
                }

                map_addr as i64
            } else if cq.result != 0 {
                // Anonymous mmap: central chose the address via PageManager.
                // Use MAP_FIXED at central's chosen address.
                unsafe {
                    libc::syscall(
                        libc::SYS_mmap,
                        cq.result as usize,
                        args[1] as usize,
                        args[2] as i32,
                        (args[3] as i32) | libc::MAP_FIXED,
                        args[4] as i32,
                        args[5] as i64,
                    )
                }
            } else {
                // cq.result == 0 means "execute with original args" (e.g. anonymous
                // mmap where central returned the address in result but it was 0).
                // Fall through to raw syscall.
                unsafe {
                    libc::syscall(
                        libc::SYS_mmap,
                        args[0] as usize,
                        args[1] as usize,
                        args[2] as i32,
                        args[3] as i32,
                        args[4] as i32,
                        args[5] as i64,
                    )
                }
            }
        },
```

**Step 3: Update handler.rs to pass ring_base and layout**

In `litebox_micro/src/handler.rs:155`, change:
```rust
        let result = unsafe { execute_locally(args.nr as u32, &args.args, &cq) };
```
to:
```rust
        let micro = unsafe { &*(*tls).micro };
        let result = unsafe {
            execute_locally(
                args.nr as u32,
                &args.args,
                &cq,
                micro.ring_base,
                &micro.layout,
            )
        };
```

**Step 4: Update existing tests to pass the new parameters**

In `litebox_micro/src/local_exec.rs`, update the test helper calls:
```rust
        let result = unsafe {
            execute_locally(
                libc::SYS_mmap as u32, &args, &cq,
                core::ptr::null_mut(), &litebox_ipc::ring::SharedRingLayout::default_layout(),
            )
        };
```
(Same for the unmap_result and unknown_returns_enosys tests.)

**Step 5: Run tests**

Run: `cargo nextest run -p litebox_micro`
Expected: All tests pass.

**Step 6: Commit**

```
git add litebox_micro/src/local_exec.rs litebox_micro/src/handler.rs
git commit -m "feat(micro): handle file-backed mmap with HAS_DATA and MAP_FIXED

execute_locally now accepts ring_base and layout for accessing the
shared data region. mmap with HAS_DATA creates an anonymous mapping
at central's chosen address, copies file content from the data
region, and sets final permissions. Anonymous mmap uses MAP_FIXED
at the address central chose via PageManager."
```

---

## Task 5: Add pointer-bearing syscalls to `needs_local_exec`

Several syscalls that the dynamic linker uses dereference guest stack/heap pointers. Central cannot dereference those (they're in micro's address space), so they must be routed to micro for local execution. Also add `arch_prctl` which the dynamic linker calls for `SET_FS`.

**Files:**
- Modify: `litebox_central/src/server.rs:337-355` (needs_local_exec)
- Modify: `litebox_micro/src/local_exec.rs` (add handlers for new syscalls)

**Step 1: Expand `needs_local_exec` in server.rs**

Replace the `needs_local_exec` method (lines 337-355):

```rust
    fn needs_local_exec(nr: u32) -> bool {
        matches!(
            i64::from(nr),
            // I/O syscalls: dereference guest buffers
            libc::SYS_read
                | libc::SYS_write
                | libc::SYS_readv
                | libc::SYS_writev
                | libc::SYS_pread64
                | libc::SYS_pwrite64
                | libc::SYS_preadv
                | libc::SYS_pwritev
                | libc::SYS_preadv2
                | libc::SYS_pwritev2
                | libc::SYS_recvfrom
                | libc::SYS_sendto
                | libc::SYS_recvmsg
                | libc::SYS_sendmsg
                // Stat syscalls: write to guest stat buffer
                | libc::SYS_fstat
                | libc::SYS_newfstatat
                // Arch/thread syscalls: must execute in guest context
                | libc::SYS_arch_prctl
                | libc::SYS_set_tid_address
                | libc::SYS_set_robust_list
                | libc::SYS_rseq
                // Resource limit: dereference guest rlimit struct
                | libc::SYS_prlimit64
                // Random: writes to guest buffer
                | libc::SYS_getrandom
                // Signal: dereference guest sigaction/sigset structs
                | libc::SYS_rt_sigaction
                | libc::SYS_rt_sigprocmask
                // Sched: dereference guest cpu_set buffer
                | libc::SYS_sched_getaffinity
                // Time: writes to guest timespec/timeval
                | libc::SYS_clock_gettime
                | libc::SYS_gettimeofday
        )
    }
```

**Step 2: Add handlers in micro's `execute_locally`**

Add new arms in `litebox_micro/src/local_exec.rs` before the `_ => -ENOSYS` fallback:

```rust
        nr if nr == libc::SYS_fstat as u32 => unsafe {
            libc::syscall(libc::SYS_fstat, args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_newfstatat as u32 => unsafe {
            libc::syscall(
                libc::SYS_newfstatat,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as i32,
            )
        },
        nr if nr == libc::SYS_set_tid_address as u32 => unsafe {
            libc::syscall(libc::SYS_set_tid_address, args[0] as usize)
        },
        nr if nr == libc::SYS_set_robust_list as u32 => unsafe {
            libc::syscall(libc::SYS_set_robust_list, args[0] as usize, args[1] as usize)
        },
        nr if nr == libc::SYS_rseq as u32 => unsafe {
            libc::syscall(
                libc::SYS_rseq,
                args[0] as usize,
                args[1] as u32,
                args[2] as i32,
                args[3] as u32,
            )
        },
        nr if nr == libc::SYS_prlimit64 as u32 => unsafe {
            libc::syscall(
                libc::SYS_prlimit64,
                args[0] as i32,
                args[1] as i32,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_getrandom as u32 => unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                args[0] as usize,
                args[1] as usize,
                args[2] as u32,
            )
        },
        nr if nr == libc::SYS_rt_sigaction as u32 => unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_rt_sigprocmask as u32 => unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as usize,
            )
        },
        nr if nr == libc::SYS_sched_getaffinity as u32 => unsafe {
            libc::syscall(
                libc::SYS_sched_getaffinity,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
            )
        },
        nr if nr == libc::SYS_clock_gettime as u32 => unsafe {
            libc::syscall(libc::SYS_clock_gettime, args[0] as i32, args[1] as usize)
        },
        nr if nr == libc::SYS_gettimeofday as u32 => unsafe {
            libc::syscall(libc::SYS_gettimeofday, args[0] as usize, args[1] as usize)
        },
        nr if nr == libc::SYS_pread64 as u32 => unsafe {
            libc::syscall(
                libc::SYS_pread64,
                args[0] as i32,
                args[1] as usize,
                args[2] as usize,
                args[3] as i64,
            )
        },
```

**Step 3: Run tests and clippy**

Run: `cargo clippy -p litebox_central -p litebox_micro && cargo nextest run -p litebox_micro`
Expected: Clean build, all tests pass.

**Step 4: Commit**

```
git add litebox_central/src/server.rs litebox_micro/src/local_exec.rs
git commit -m "feat: route pointer-bearing syscalls through needs_local_exec

Add fstat, newfstatat, arch_prctl, set_tid_address, set_robust_list,
rseq, prlimit64, getrandom, rt_sigaction, rt_sigprocmask,
sched_getaffinity, clock_gettime, gettimeofday, and pread64 to the
needs_local_exec list. These syscalls dereference guest memory that
is only valid in micro's address space. Add corresponding handlers
in micro's execute_locally."
```

---

## Task 5b: Handle `access` and `openat` pathname syscalls

The dynamic linker calls `access("/etc/ld.so.preload", ...)` and `openat(-1, "/etc/ld.so.cache", ...)` which dereference pathname pointers. These currently go to central's shim which calls `to_cstring()` → `to_owned_slice()` — now that GuestConstPtr is fixed, these will work IF central's process has the path string in its address space. But the pathname is in the *guest's* stack, not central's memory.

**Decision:** Route `access` and `openat` syscalls to central (they need the shim's filesystem), but since the pathname is a guest pointer, central will now be able to read it IF the address is valid in central. In the micro-litebox architecture, the guest's stack is in micro's address space only. So these MUST go through `needs_local_exec`.

However, `openat` and `access` need the LiteBox filesystem, not the host FS. If we route them to `needs_local_exec`, micro will call the real kernel `openat`/`access` which bypasses LiteBox's VFS entirely.

**The correct solution:** We need a "data transfer" pattern — micro reads the pathname string from guest memory, sends it to central via the SQ data region, and central uses it for the shim call. This is complex.

**Simpler approach for the hello-world milestone:** Make `access` return `-ENOENT` (the dynamic linker handles this gracefully for `/etc/ld.so.preload`) and route `openat` through the shim — since the dynamic linker opens files whose paths are embedded in the ELF (not on the guest stack), we need to check whether those paths are in mapped memory accessible from central.

**Actually, the simplest correct approach:** The pathname pointers for `openat`/`access` come from the ELF's string tables, which ARE in central's address space (central loaded the ELF via the shim's mmap). So GuestConstPtr dereference will work for these cases. For paths on the guest's stack (e.g. user-provided paths), they would segfault — but the hello world test doesn't do that.

**For this milestone, leave `openat` and `access` dispatched to the shim (the default path). The GuestConstPtr fix from Task 1 makes this work for paths in mapped ELF segments. Add a comment documenting the limitation.**

**Files:**
- Modify: `litebox_central/src/server.rs` — add a comment above the default dispatch path

**Step 1: Add explanatory comment**

After the `is_mm_syscall` block in `handle_syscall`, before the default dispatch (around line 247-249 after Task 3's changes), add:

```rust
        // Syscalls that dereference pathname pointers (openat, access, stat,
        // etc.) work for paths in ELF-mapped memory (which is also mapped in
        // central's address space). Guest stack pointers will segfault — a
        // full solution requires data transfer via the SQ data region.
```

**Step 2: Commit**

```
git add litebox_central/src/server.rs
git commit -m "docs(central): document pathname pointer limitation for Phase E"
```

---

## Task 6: Initialize brk from ELF loader

The launcher loads the ELF and knows the `brk` address (`MappingInfo.brk`). Central's PageManager needs this value before the first `brk()` syscall. Pass it via a CLI argument.

**Files:**
- Modify: `litebox_launcher/src/load_elf.rs:48-53` (add `brk` to `LoadedElf`)
- Modify: `litebox_launcher/src/load_elf.rs:164-178` (capture `main_info.brk`)
- Modify: `litebox_launcher/src/main.rs` (pass brk to central via CLI)
- Modify: `litebox_launcher/src/central.rs:80-85` (add `--initial-brk` arg)
- Modify: `litebox_central/src/main.rs:27-33` (parse `--initial-brk`)
- Modify: `litebox_central/src/server.rs` (call `set_initial_brk` before serving)

**Step 1: Add `brk` to `LoadedElf`**

In `litebox_launcher/src/load_elf.rs`, change the `LoadedElf` struct:

```rust
pub struct LoadedElf {
    pub entry_point: usize,
    pub stack_pointer: usize,
    /// Program break address (end of mapped segments).
    pub brk: usize,
}
```

**Step 2: Return `brk` from `load_elf`**

In the same file, where `LoadedElf` is constructed (find the return site), add `brk: main_info.brk`.

Search for the `LoadedElf {` construction and add the brk field.

**Step 3: Pass brk to central via CLI**

In `litebox_launcher/src/central.rs`, modify `spawn()` to accept `initial_brk: usize`:

```rust
    pub fn spawn(shmem_fd: i32, initial_brk: usize) -> anyhow::Result<Self> {
```

Add the `--initial-brk` arg to the exec args:

```rust
                let fd_arg = format!("--shmem-fd={shmem_fd}");
                let brk_arg = format!("--initial-brk={initial_brk}");
                // ...
                let c_arg2 = CString::new(brk_arg).unwrap();
                let args = [c_arg0.as_ptr(), c_arg1.as_ptr(), c_arg2.as_ptr(), std::ptr::null()];
```

**Step 4: Parse `--initial-brk` in central**

In `litebox_central/src/main.rs`, add to the `Args` struct:

```rust
    /// Initial program break address from the ELF loader.
    #[arg(long, default_value = "0")]
    initial_brk: usize,
```

**Step 5: Call `set_initial_brk` after task creation**

In `litebox_central/src/main.rs`, after `let task = shim.create_task(...)` and before creating the server:

```rust
    if args.initial_brk != 0 {
        task.set_initial_brk(args.initial_brk);
    }
```

Note: `LinuxShimTask` may not expose `set_initial_brk` directly. Check the `LinuxShimTask` API. If not, we may need to access the underlying `PageManager` through the task's `GlobalState`. Alternatively, the `ProcessServer` can handle it. Research the exact API.

The `PageManager::set_initial_brk` is at `litebox/src/mm/mod.rs:289`. It's called via `global.pm.set_initial_brk(info.brk)` in the shim. We need a way to call it from outside the shim.

**Alternative approach:** Add a `set_initial_brk` method to `ProcessServer` that delegates to the task's global state:

In `litebox_central/src/server.rs`, add:
```rust
    /// Set the initial program break address in the PageManager.
    ///
    /// Must be called before serving any `brk()` syscalls. Panics if
    /// called after brk is already initialized.
    pub fn set_initial_brk(&self, brk: usize) {
        self.primary_task.global().pm.set_initial_brk(brk);
    }
```

Check if `LinuxShimTask` has a `global()` method. If it does, this works. If not, we need to find the path.

In `litebox_central/src/main.rs`, after creating the server:
```rust
    if args.initial_brk != 0 {
        server.set_initial_brk(args.initial_brk);
    }
```

**Step 6: Update launcher main.rs**

In `litebox_launcher/src/main.rs`, change:
```rust
    let central = central::CentralProcess::spawn(shmem.fd_raw())?;
```
to:
```rust
    // Load the ELF first to get brk, then spawn central with it.
```

Actually, the order matters. Currently: spawn central → load ELF → jump. We need brk before spawning central. But ELF loading currently happens after central spawns.

**Reorder:** Load ELF first (the ELF is loaded into the launcher's address space, not central's), then spawn central with the brk value. The ELF loading doesn't need central — it uses the real kernel's mmap directly.

New order in main.rs:
1. Create shmem
2. Load ELF (get brk)
3. Spawn central (pass brk)
4. Init micro
5. Jump to guest

```rust
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        anyhow::bail!("Usage: litebox_launcher <elf-path> [args...]");
    }
    let elf_path = &args[1];

    // 1. Create shared memory region for IPC ring buffer.
    let shmem = shmem::LauncherSharedRegion::new()?;

    // 2. Load the guest ELF binary (to get brk address for central).
    let syscall_entry = litebox_micro::get_syscall_entry_point();
    let guest_argv: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    let guest_envp: Vec<&str> = Vec::new();
    let loaded = load_elf::load_elf(elf_path, &guest_argv, &guest_envp, syscall_entry)?;

    // 3. Spawn central process (child inherits shmem fd, gets initial brk).
    let central = central::CentralProcess::spawn(shmem.fd_raw(), loaded.brk)?;
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 4. Initialize micro-LiteBox.
    unsafe {
        litebox_micro::micro_init(
            shmem.fd_raw(),
            shmem.base_ptr(),
            shmem.layout().total_size,
            1, 0,
            central.pid().cast_unsigned(),
        );
    }
    unsafe { litebox_micro::micro_init_thread(0) };

    // 5. Jump to guest.
    unsafe { entry::jump_to_guest(loaded.entry_point, loaded.stack_pointer) }
}
```

**Step 7: Update the central spawn test**

In `litebox_launcher/src/central.rs`, update the test:
```rust
        let proc = CentralProcess::spawn(0, 0).expect("spawn should succeed");
```

**Step 8: Run tests**

Run: `cargo nextest run -p litebox_launcher -p litebox_central`
Expected: All tests pass.

**Step 9: Commit**

```
git add litebox_launcher/src/load_elf.rs litebox_launcher/src/main.rs \
        litebox_launcher/src/central.rs litebox_central/src/main.rs \
        litebox_central/src/server.rs
git commit -m "feat: initialize brk from ELF loader via --initial-brk

The launcher loads the ELF, extracts MappingInfo.brk, and passes it
to central via --initial-brk CLI arg. Central calls set_initial_brk
on the PageManager before serving syscalls. Reorders launcher to
load ELF before spawning central."
```

---

## Task 7: Add tar_ro filesystem layer for shared libraries

The dynamic linker needs to find `libc.so.6` and other shared libraries. Central's filesystem needs a `tar_ro` layer containing the rootfs tar produced by the packager.

**Files:**
- Modify: `litebox_central/src/main.rs` (add `--rootfs-tar` CLI arg, construct 3-layer FS)
- Modify: `litebox_launcher/src/central.rs` (pass `--rootfs-tar` to central)
- Modify: `litebox_launcher/src/main.rs` (accept rootfs tar path)

**Step 1: Add `--rootfs-tar` to central's CLI**

In `litebox_central/src/main.rs`, add to `Args`:
```rust
    /// Path to a .tar file containing the root filesystem (shared libraries, etc.).
    #[arg(long)]
    rootfs_tar: Option<String>,
```

**Step 2: Change the CentralFs type to support 3 layers**

The FS type needs to accommodate the optional tar_ro layer. When `--rootfs-tar` is provided, construct:
`layered(in_mem, layered(devices, tar_ro))` — matching the runner pattern.

When not provided, keep the current: `layered(devices, in_mem)`.

This is tricky because the type alias `CentralFs` is fixed at compile time. Use a feature flag, or use `Box<dyn ...>`, or always construct the 3-layer type (using `EMPTY_TAR_FILE` when no tar is provided).

**Simplest approach:** Always construct the 3-layer FS. When no tar is provided, use `litebox::fs::tar_ro::EMPTY_TAR_FILE`. This avoids type gymnastics.

Change the type alias:
```rust
type CentralFs = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::devices::FileSystem<Platform>,
        litebox::fs::tar_ro::FileSystem<Platform>,
    >,
>;
```

Change FS construction in `main()`:
```rust
    let tar_data: std::borrow::Cow<'static, [u8]> = if let Some(ref tar_path) = args.rootfs_tar {
        let data = std::fs::read(tar_path)
            .map_err(|e| anyhow::anyhow!("failed to read rootfs tar {tar_path}: {e}"))?;
        std::borrow::Cow::Owned(data)
    } else {
        std::borrow::Cow::Borrowed(litebox::fs::tar_ro::EMPTY_TAR_FILE)
    };

    let devices = litebox::fs::devices::FileSystem::new(lb);
    let in_mem = litebox::fs::in_mem::FileSystem::new(lb);
    let tar_ro = litebox::fs::tar_ro::FileSystem::new(lb, tar_data);
    let inner = litebox::fs::layered::FileSystem::new(
        lb,
        devices,
        tar_ro,
        litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
    );
    let fs = std::sync::Arc::new(litebox::fs::layered::FileSystem::new(
        lb,
        in_mem,
        inner,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    ));
```

**Step 3: Pass `--rootfs-tar` from launcher to central**

In `litebox_launcher/src/central.rs`, modify `spawn()` to accept `rootfs_tar: Option<&str>`:

```rust
    pub fn spawn(shmem_fd: i32, initial_brk: usize, rootfs_tar: Option<&str>) -> anyhow::Result<Self> {
```

Build the args list dynamically:
```rust
                let fd_arg = format!("--shmem-fd={shmem_fd}");
                let brk_arg = format!("--initial-brk={initial_brk}");
                let central_path = find_central_binary();
                let c_path = CString::new(central_path).unwrap();
                let c_arg0 = CString::new("litebox_central").unwrap();
                let c_fd = CString::new(fd_arg).unwrap();
                let c_brk = CString::new(brk_arg).unwrap();

                let mut arg_ptrs: Vec<*const libc::c_char> =
                    vec![c_arg0.as_ptr(), c_fd.as_ptr(), c_brk.as_ptr()];

                let c_tar;
                if let Some(tar_path) = rootfs_tar {
                    let tar_arg = format!("--rootfs-tar={tar_path}");
                    c_tar = CString::new(tar_arg).unwrap();
                    arg_ptrs.push(c_tar.as_ptr());
                }
                // Note: c_tar must live long enough. Since we exec immediately,
                // this is fine — the CStrings live on the stack until execvp.
                // But Rust may warn about unused assignments if the branch
                // isn't taken. Use MaybeUninit or declare before the if.

                arg_ptrs.push(std::ptr::null());
                unsafe { libc::execvp(c_path.as_ptr(), arg_ptrs.as_ptr()) };
```

Wait — there's a subtlety: `c_tar` is only initialized inside the `if` branch, but `arg_ptrs` needs the pointer which must remain valid until `execvp`. The cleanest approach:

```rust
                let c_tar_arg = rootfs_tar.map(|p| CString::new(format!("--rootfs-tar={p}")).unwrap());
                if let Some(ref c_tar) = c_tar_arg {
                    arg_ptrs.push(c_tar.as_ptr());
                }
```

**Step 4: Update launcher main.rs to accept rootfs_tar**

Add `--rootfs-tar` to the launcher's CLI. Currently it uses raw `std::env::args()`. For simplicity, check for `--rootfs-tar=<path>` in the args:

```rust
    let rootfs_tar = args.iter()
        .find(|a| a.starts_with("--rootfs-tar="))
        .map(|a| a.strip_prefix("--rootfs-tar=").unwrap().to_string());
```

Or use `clap` if already available. Check the launcher's dependencies. If not, do simple manual parsing.

Pass to central:
```rust
    let central = central::CentralProcess::spawn(
        shmem.fd_raw(), loaded.brk, rootfs_tar.as_deref()
    )?;
```

**Step 5: Update existing tests**

Fix `central::tests::spawn_and_wait`:
```rust
        let proc = CentralProcess::spawn(0, 0, None).expect("spawn should succeed");
```

**Step 6: Run tests and clippy**

Run: `cargo clippy -p litebox_central -p litebox_launcher && cargo nextest run -p litebox_launcher -p litebox_central`
Expected: Clean.

**Step 7: Commit**

```
git add litebox_central/src/main.rs litebox_launcher/src/central.rs litebox_launcher/src/main.rs
git commit -m "feat: add tar_ro filesystem layer for dynamic linker support

Central accepts --rootfs-tar CLI arg pointing to a .tar with shared
libraries. Constructs layered(in_mem, layered(devices, tar_ro))
filesystem. Uses EMPTY_TAR_FILE when no tar provided. Launcher
passes the tar path through to central."
```

---

## Task 8: Add `ld.so.cache` / `ld.so.preload` handling

The dynamic linker calls `access("/etc/ld.so.preload", F_OK)` — this must return `-ENOENT`. It also calls `openat(-100, "/etc/ld.so.cache", ...)` — this can also return `-ENOENT` (the dynamic linker falls back to searching `DT_RPATH`/`DT_RUNPATH`).

With the tar_ro filesystem from Task 7, if the packager includes `/etc/ld.so.cache` in the tar, this works automatically. If not, the shim returns `-ENOENT` which is correct behavior.

**Check:** Does the packager include `/etc/ld.so.cache`? If not, this task is a no-op (the shim's VFS returns `-ENOENT` for missing files, which the linker handles gracefully).

**This task is likely a no-op.** Verify during integration testing (Task 9). If the dynamic linker can't find libc.so.6 via the cache, it falls back to searching `DT_RUNPATH` which the packager sets up.

No code changes needed. Skip to Task 9.

---

## Task 9: Integration test — dynamic hello world end-to-end

Compile a dynamic hello world, package it with `litebox_packager`, and run it through `litebox_launcher`.

**Files:**
- Create: `litebox_launcher/tests/hello_dynamic.c`
- Modify: `litebox_launcher/tests/integration.rs` (add `test_dynamic_hello_world`)
- Modify: `litebox_launcher/tests/.gitignore`

**Step 1: Write the test binary**

Create `litebox_launcher/tests/hello_dynamic.c`:
```c
#include <stdio.h>

int main(void) {
    puts("Hello from dynamic libc!");
    return 0;
}
```

**Step 2: Write the integration test**

Add to `litebox_launcher/tests/integration.rs`:

```rust
#[test]
fn test_dynamic_hello_world() {
    // 1. Compile the dynamic C program.
    let tests_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let binary = tests_dir.join("hello_dynamic");
    let status = std::process::Command::new("gcc")
        .args(["-o", binary.to_str().unwrap(), "hello_dynamic.c"])
        .current_dir(&tests_dir)
        .status()
        .expect("gcc should be available");
    assert!(status.success(), "gcc failed");

    // 2. Package with litebox_packager (rewrite ELF + bundle shared libs).
    let tar_path = tests_dir.join("hello_dynamic.tar");
    let rewritten = tests_dir.join("hello_dynamic.rewritten");

    // Use litebox_packager CLI or library.
    // The packager produces: rewritten ELF + .tar with all shared libs.
    let status = std::process::Command::new(
        env!("CARGO_BIN_EXE_litebox_packager")  // requires [[bin]] in litebox_packager
    )
    .args([
        binary.to_str().unwrap(),
        "--output", rewritten.to_str().unwrap(),
        "--tar", tar_path.to_str().unwrap(),
    ])
    .status()
    .expect("litebox_packager should be available");
    assert!(status.success(), "litebox_packager failed");

    // 3. Run through litebox_launcher.
    let launcher = env!("CARGO_BIN_EXE_litebox_launcher");
    let output = std::process::Command::new(launcher)
        .args([
            rewritten.to_str().unwrap(),
            &format!("--rootfs-tar={}", tar_path.display()),
        ])
        .output()
        .expect("litebox_launcher should run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Hello from dynamic libc!"),
        "Expected 'Hello from dynamic libc!' in stdout, got: {stdout}"
    );
    assert!(output.status.success(), "launcher exited with non-zero status");
}
```

**Note:** The exact packager CLI interface may differ. Check `litebox_packager`'s actual binary name and argument format. The test may need adjustment based on how the packager works.

**Alternative if packager is a library, not a binary:** Call the library directly:
```rust
    litebox_packager::pack_for_litebox(&binary, &rewritten, &tar_path)?;
```

**Step 3: Update .gitignore**

Add to `litebox_launcher/tests/.gitignore`:
```
hello_dynamic
hello_dynamic.rewritten
hello_dynamic.tar
```

**Step 4: Run the test**

Run: `cargo nextest run -p litebox_launcher test_dynamic_hello_world`
Expected: "Hello from dynamic libc!" in stdout.

**Step 5: Debug and iterate**

This test will likely reveal additional issues. Common problems:
- Missing syscall in `needs_local_exec` → add it
- PageManager address conflict → adjust reserved regions
- Data region too small for a mapping → increase `DEFAULT_DATA_REGION_SIZE` or implement chunking
- Central segfault on guest pointer → add the syscall to `needs_local_exec`

Use `strace` on the launcher process to debug:
```bash
strace -f -o /tmp/trace.txt cargo nextest run -p litebox_launcher test_dynamic_hello_world
```

**Step 6: Commit**

```
git add litebox_launcher/tests/hello_dynamic.c litebox_launcher/tests/integration.rs \
        litebox_launcher/tests/.gitignore
git commit -m "test(launcher): add dynamic hello world integration test

Compiles a dynamic C program, packages it with litebox_packager
(rewriting syscalls + bundling shared libs), and runs it through
litebox_launcher with the tar_ro filesystem."
```

---

## Summary of Tasks

| # | Task | Files | Key Change |
|---|------|-------|------------|
| 1 | Fix GuestConstPtr/GuestMutPtr | `litebox_platform_central/src/lib.rs` | Raw pointer dereference for 6 methods |
| 2 | Add `data_region_mut()` | `litebox_central/src/shmem.rs` | Mutable data region access |
| 3 | Dual-dispatch for MM syscalls | `litebox_central/src/server.rs` | mmap/munmap/mprotect/brk through shim + EXEC_LOCAL |
| 4 | Micro file-backed mmap | `litebox_micro/src/{local_exec,handler}.rs` | MAP_FIXED + HAS_DATA copy |
| 5 | Expand needs_local_exec | `litebox_central/src/server.rs`, `litebox_micro/src/local_exec.rs` | fstat, arch_prctl, getrandom, etc. |
| 5b| Pathname syscall docs | `litebox_central/src/server.rs` | Comment about openat/access limitation |
| 6 | Initialize brk | launcher + central | `--initial-brk` CLI, `set_initial_brk` call |
| 7 | tar_ro filesystem | `litebox_central/src/main.rs`, launcher | `--rootfs-tar` CLI, 3-layer FS |
| 8 | ld.so.cache handling | (likely no-op) | Verify during integration test |
| 9 | Integration test | `litebox_launcher/tests/` | Dynamic hello world end-to-end |
