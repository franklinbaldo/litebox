# File-Backed mmap in Central/Micro Architecture — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make file-backed mmap work end-to-end in the central/micro architecture by fixing CentralPlatform's `GuestMutPtr` to dereference real memory, then transferring the initialized data to micro.

**Architecture:** Central's `allocate_pages` already maps real memory in its own address space via `libc::mmap`. We fix `GuestMutPtr`/`GuestConstPtr` to dereference these addresses (they're valid in central's process). After the shim populates pages with file content, central serializes the data into the shared memory data region and tells micro to create a matching mapping and copy the data in. For mappings larger than the data region, data is sent in chunks via multiple round-trips.

**Tech Stack:** Rust, libc, shared memory IPC ring buffer, memfd

---

## Analysis of Current State

### 1. Unimplemented GuestMutPtr/GuestConstPtr Methods

All six methods on `GuestConstPtr<T>` and `GuestMutPtr<T>` in `litebox_platform_central/src/lib.rs` panic with `unimplemented!()`:

| Type | Trait | Method | Line | What it needs to do |
|------|-------|--------|------|---------------------|
| `GuestConstPtr<T>` | `RawConstPointer<T>` | `read_at_offset(self, count: isize) -> Option<T>` | 247-251 | Read `T` at `self.addr + count * size_of::<T>()` via raw pointer |
| `GuestConstPtr<T>` | `RawConstPointer<T>` | `to_owned_slice(self, len: usize) -> Option<Box<[T]>>` | 253-257 | Copy `len` elements starting at `self.addr` into a heap-allocated boxed slice |
| `GuestMutPtr<T>` | `RawConstPointer<T>` | `read_at_offset(self, count: isize) -> Option<T>` | 296-299 | Same as GuestConstPtr (read via raw pointer) |
| `GuestMutPtr<T>` | `RawConstPointer<T>` | `to_owned_slice(self, len: usize) -> Option<Box<[T]>>` | 302-306 | Same as GuestConstPtr (copy to boxed slice) |
| `GuestMutPtr<T>` | `RawMutPointer<T>` | `write_at_offset(self, count: isize, value: T) -> Option<()>` | 310-311 | Write `value` at `self.addr + count * size_of::<T>()` via raw pointer |
| `GuestMutPtr<T>` | `RawMutPointer<T>` | `mutate_subslice_with(self, range, f) -> Option<R>` | 314-322 | Create a mutable slice from `self.addr` covering `range`, call `f` on it |

**Note:** `copy_from_slice` (used by the mmap memcpy path at `litebox_shim_linux/src/syscalls/mm.rs:225`) delegates to `mutate_subslice_with` via the default implementation in `litebox/src/platform/mod.rs:594-605`.

### 2. The mmap Flow Through Central

Currently, mmap is **NOT** in `needs_local_exec` (`server.rs:337-355`). This means mmap goes through `dispatch_to_task` → `dispatch_syscall` → `sys_mmap`. The flow:

1. **Anonymous mmap**: `sys_mmap` → `do_mmap_anonymous` → `do_mmap` → `PageManager::create_*_pages` → `CentralPlatform::allocate_pages` → real `libc::mmap` in central's address space. The `op` closure is `|_| Ok(0)` (no-op), so no pointer dereference needed. **This already works.**

2. **File-backed mmap**: `sys_mmap` → `do_mmap_file` → tries CoW first (via `try_cow_mmap_file`, which calls `try_allocate_cow_pages` — returns `UnsupportedByPlatform` on CentralPlatform) → falls back to `do_mmap_file_memcpy`. This path:
   - Calls `do_mmap` which allocates pages with `ProtFlags::PROT_READ_WRITE`
   - The `op` closure reads file content via `sys_read` into a stack buffer
   - Then calls `ptr.copy_from_slice(copied, &buffer[..size])` — **THIS PANICS** because `copy_from_slice` → `mutate_subslice_with` → `unimplemented!()`
   - After the closure, `PageManager` changes perms to the requested final permissions

3. After `dispatch_syscall` returns, central gets the mapped address (in central's address space) as `cq.result`. Central writes this to the CqEntry. Micro receives it as a return value.

**The problem**: Even if we fix GuestMutPtr, the returned address is in central's address space, not micro's. Micro can't use it directly.

### 3. The Data Region

The shared memory data region is **4 MiB** by default (`litebox_ipc/src/ring.rs:25: DEFAULT_DATA_REGION_SIZE = 4 * 1024 * 1024`).

File-backed mmap sizes:
- Typical: `libc.so.6` segments can be 1-2 MiB
- Large: `libc.so.6` total can be ~2 MiB, but individual mmap calls are usually per-segment (~200 KB to ~1.5 MiB)
- Worst case: a single mmap of the entire file could be many MiB

**4 MiB is sufficient for most individual mmap calls** but not all. We need a chunking mechanism for safety.

### 4. Other Syscall Handlers That Use GuestMutPtr

Searching `litebox_shim_linux/src/lib.rs` and `litebox_shim_linux/src/syscalls/` for all uses of pointer dereference operations that would flow through central:

**Already handled by `needs_local_exec`** (these go EXEC_LOCAL, so micro dereferences):
- `read`, `write`, `readv`, `writev`, `pread64`, `pwrite64`, `preadv/2`, `pwritev/2`
- `recvfrom`, `sendto`, `recvmsg`, `sendmsg`

**Dispatched through central (NOT in needs_local_exec) and use pointer ops:**
- `sys_mmap` file-backed path: `copy_from_slice` — **WILL PANIC** (this is the focus)
- `stat/fstat/lstat/fstatat`: `buf.write_at_offset(0, stat)` — **WILL PANIC**
- `pipe2`: `pipefd.write_at_offset(0/1, fd)` — **WILL PANIC**
- `rt_sigprocmask`: `oldset_ptr.write_at_offset(0, oldset)` — **WILL PANIC**
- `sigaltstack`: `old_ss_ptr.write_at_offset`, `ss_ptr.read_at_offset` — **WILL PANIC**
- `rt_sigaction`: `act_ptr.read_at_offset`, `oldact_ptr.write_at_offset` — **WILL PANIC**
- `set_robust_list`: `head_ptr.write_at_offset` — **WILL PANIC**
- `get_robust_list`: `len.write_at_offset` — **WILL PANIC**
- `sysinfo`: `buf.write_at_offset(0, sysinfo)` — **WILL PANIC**
- `arch_prctl` (`ARCH_GET_FS`): `addr.write_at_offset` — **WILL PANIC**
- `uname`: `buf.copy_from_slice` — **WILL PANIC**
- `capget`: `data_ptr.write_at_offset` — **WILL PANIC**
- `prctl` (`PR_SET_NAME`/`PR_GET_NAME`): `read_at_offset`/`write_slice_at_offset` — **WILL PANIC**
- `prlimit64`: `rlim.read_at_offset`/`write_at_offset` — **WILL PANIC**
- `getrlimit`/`setrlimit`: `rlim.write_at_offset`/`read_at_offset` — **WILL PANIC**
- `gettimeofday`: `tv.write_at_offset` — **WILL PANIC**
- `clock_gettime`: pointer ops — **WILL PANIC**
- `getrandom`: `buf.copy_from_slice` — **WILL PANIC**
- `sched_getaffinity`: `mask.copy_from_slice` — **WILL PANIC**
- `socketpair`: `sockvec.write_at_offset` — **WILL PANIC**
- Various socket ops with address structs

**These currently don't hit panics only because those syscalls either haven't been tested yet, or the test programs (nolibc binaries) don't use them.**

### 5. Design Decision: Fix GuestMutPtr for ALL Pointer Operations

Since `allocate_pages` maps real memory in central's address space, AND many other syscalls besides mmap use pointer dereferences on addresses that are either:
- Addresses of memory that central allocated (mmap'd pages), or  
- Stack/heap addresses that are in micro's address space (NOT accessible from central)

We need to be careful. For mmap specifically, the pointer returned by `allocate_pages` is in central's address space, so dereferencing works. But for `stat(path, &buf)`, `buf` is a guest stack pointer — central can't dereference it.

**This means we cannot blindly fix ALL GuestMutPtr methods.** We have two strategies:

**Strategy A (chosen — targeted fix):** Only fix GuestMutPtr to dereference for the mmap file-content-copy path. Other syscalls that need guest pointer access should be added to `needs_local_exec` or handled via the data region.

**Strategy B (alternative):** Fix GuestMutPtr to attempt dereference but return `None` on SIGSEGV (like the userland platform does). This is more complex and risky in central's server process.

**We go with Strategy A:** Fix GuestMutPtr's pointer methods to do real derefs (since it's sound for central-allocated memory), but also add syscalls that pass *guest* pointers to `needs_local_exec`. The mmap case is special because central allocates the pages itself, so the pointers are valid.

---

## Design

### Phase 1: Fix GuestMutPtr/GuestConstPtr (Simple Raw Pointer Dereference)

Implement all six unimplemented methods as raw pointer dereferences. These will work correctly for memory that central itself allocated (e.g., via `allocate_pages`). For guest stack/heap pointers, they will segfault — but that's OK because those syscalls should be routed to `needs_local_exec` anyway.

The implementation mirrors `litebox/src/platform/trivial_providers.rs` `TransparentMutPtr`/`TransparentConstPtr`.

#### Safety consideration

The addresses stored in `GuestMutPtr` are either:
1. Returned by `CentralPlatform::allocate_pages` — **valid in central's address space**
2. Guest virtual addresses from micro — **NOT valid in central's address space**

Case (1) is safe to dereference. Case (2) will segfault. We accept this because case (2) only occurs for syscalls that should be in `needs_local_exec`.

### Phase 2: Make File-Backed mmap Work End-to-End

The key insight: for file-backed mmap, central needs to:
1. Run the shim's mmap handler (which allocates pages in central and copies file content into them)
2. Send the initialized data to micro so micro can create an equivalent mapping

#### Flow:

```
Guest calls mmap(addr, len, prot, MAP_PRIVATE, fd, offset)
  │
  ▼
Micro sends SqEntry{SYS_mmap, args=[addr, len, prot, flags, fd, offset]}
  │
  ▼
Central receives SqEntry
  │
  ├─ Is anonymous mmap? (MAP_ANONYMOUS set)
  │    ├─ YES → dispatch_to_task (shim handles it, allocates in central)
  │    │        Return EXEC_LOCAL with result=0
  │    │        Micro does: mmap(addr, len, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
  │    │        (same as today for anonymous mmap)
  │    │
  │    └─ NO → File-backed mmap (NEW PATH)
  │         1. dispatch_to_task → shim allocates pages in central, reads file → populates pages
  │         2. result = address of populated pages in central's address space  
  │         3. Central reads the populated data from its own memory
  │         4. Central sets CqEntry:
  │            - flags = EXEC_LOCAL | HAS_DATA
  │            - result = shim's return value (mapped address in central, for PageManager consistency)
  │            - data_offset/data_len for inline data (if it fits in data region)
  │         5. Central writes file content into shared memory data region
  │         6. Central munmaps its local copy
  │         7. Micro receives CqEntry:
  │            - Sees EXEC_LOCAL | HAS_DATA
  │            - mmap(addr, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0)
  │            - memcpy data from shared data region into the new mapping
  │            - mprotect to final permissions
  │            - Returns the mapped address to guest
```

#### Why EXEC_LOCAL is needed:

Micro must create the mapping in its own address space. Central can't do that remotely. So central tells micro "execute locally" but also provides the file content.

#### Why HAS_DATA is needed:

We need to distinguish between:
- EXEC_LOCAL without data (e.g., anonymous mmap, exit, write): micro executes the raw syscall
- EXEC_LOCAL with data (e.g., file-backed mmap): micro creates anonymous mapping + copies data

### Phase 3: Chunked Data Transfer for Large Mappings

For mappings larger than the data region (4 MiB), we need chunking. Two approaches:

**Approach A (Multiple CQ entries):** Central sends the first chunk in the initial CqEntry, then micro requests more chunks. Complex, breaks the 1:1 SQ→CQ model.

**Approach B (Single CQ + micro pulls data):** Central writes data to the data region, signals micro via CQ. If data doesn't fit, CQ indicates "more data available". Micro reads data region, sends MSG_DATA_ACK, central writes next chunk. Repeat.

**Approach C (Simplest — expand data region or use memfd):** For large mappings, central creates a temporary memfd, writes data to it, passes the fd number to micro via CqEntry. Micro mmap's the memfd, copies data, munmaps the memfd.

**Recommended: Approach C for large mappings, inline for small.**

For the initial implementation, we use **inline data only** (fits in 4 MiB data region). A single mmap call for a file-backed mapping larger than 4 MiB will fail with ENOMEM. This is acceptable because:
- Individual ELF segment loads are typically < 2 MiB
- libc.so.6 is loaded segment-by-segment, not all at once
- We can add the memfd path later as needed

### Phase 4: CqEntry Format for File-Backed mmap

```rust
CqEntry {
    seq: <matching SqEntry>,
    result: <mapped address from central's PageManager>,  // For MSG_LOCAL_RESULT consistency
    flags: cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA,
    thread_slot: <from SqEntry>,
    _pad: [0; 4],
    data_offset: <offset into data region where file content starts>,
    data_len: <actual bytes of file content written>,
}
```

Additionally, micro needs to know:
- The guest virtual address to map at (= `result` from CqEntry, since PageManager chose it)
- The total mapping size (= original `args[1]` from the SqEntry, page-aligned)
- The final protection flags (= original `args[2]` from the SqEntry)

Micro already has the original SqEntry args, so it can reconstruct these.

### Phase 5: Micro's EXEC_LOCAL Handler for mmap with HAS_DATA

In `litebox_micro/src/local_exec.rs`, when `SYS_mmap` is received with `HAS_DATA`:

```rust
nr if nr == libc::SYS_mmap as u32 => {
    if cq.flags & cq_flags::HAS_DATA != 0 {
        // File-backed mmap: central populated the data
        let map_addr = cq.result as usize;  // Address chosen by central's PageManager
        let map_len = args[1] as usize;     // Original requested length
        let final_prot = args[2] as i32;    // Original requested prot
        let data_len = cq.data_len as usize;
        
        // 1. Create anonymous mapping at the chosen address
        let ptr = libc::mmap(
            map_addr as *mut _,
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,  // Writable for memcpy
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1, 0
        );
        
        // 2. Copy data from shared memory data region
        let data_src = ring_base.add(layout.data_region_offset + cq.data_offset as usize);
        core::ptr::copy_nonoverlapping(data_src, ptr as *mut u8, data_len);
        
        // 3. Set final permissions
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
            libc::mprotect(ptr, map_len, final_prot);
        }
        
        map_addr as i64  // Return the address to guest
    } else {
        // Anonymous mmap: execute directly
        libc::syscall(libc::SYS_mmap, ...)
    }
}
```

### Phase 6: Central's Server Changes

In `server.rs`, mmap needs special handling:

```rust
fn handle_syscall(&self, entry: &SqEntry) -> CqEntry {
    // ... existing code ...
    
    // Special handling for file-backed mmap
    if nr == libc::SYS_mmap as u32 {
        let flags = entry.args[3] as i32;
        if flags & libc::MAP_ANONYMOUS != 0 {
            // Anonymous mmap: dispatch through shim, return EXEC_LOCAL
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            cq.flags = cq_flags::EXEC_LOCAL;
            return cq;
        } else {
            // File-backed mmap: dispatch through shim, then transfer data
            let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
            let result = self.dispatch_to_task(entry.thread_slot, &mut regs);
            if result < 0 {
                // Error from shim
                cq.result = result;
                return cq;
            }
            
            let addr = result as usize;
            let len = entry.args[1] as usize;
            
            // Copy data from central's mapping to shared data region
            let data_region = self.region.data_region_mut();
            let copy_len = len.min(data_region.len());
            unsafe {
                core::ptr::copy_nonoverlapping(
                    addr as *const u8,
                    data_region.as_mut_ptr(),
                    copy_len,
                );
            }
            
            // Free central's local copy
            unsafe { libc::munmap(addr as *mut _, len); }
            // Note: we also need to tell central's PageManager to forget this mapping.
            // This is tricky — see "Open Issues" below.
            
            cq.result = result;  // The address (for micro to use as the target)
            cq.flags = cq_flags::EXEC_LOCAL | cq_flags::HAS_DATA;
            cq.data_offset = 0;
            cq.data_len = copy_len as u32;
            return cq;
        }
    }
    
    // ... rest of existing code ...
}
```

---

## Open Issues

### Issue 1: PageManager State Consistency

Central's `PageManager` tracks what's mapped where in the "guest" address space. When central's shim does `sys_mmap`, PageManager records a mapping at address X. But:
- Address X is in central's address space
- Micro will map at the same address X in micro's address space
- Central should NOT munmap address X until after data transfer
- After data transfer, central MUST munmap address X (to avoid leaking memory)
- But PageManager still thinks address X is mapped

**Solution:** After data transfer, central calls `deallocate_pages(X..X+len)` to unmap AND clears the PageManager entry. But `deallocate_pages` is the raw platform operation; PageManager's `remove_pages` would be the proper way. We need to be careful not to double-free.

Actually, a simpler approach: central does NOT munmap/deregister the mapping from PageManager. Let PageManager think it's still mapped. The next time the guest does munmap on that address, central's shim will call `remove_pages` which will:
1. Update PageManager's internal tracking (remove the VMA)
2. Call `deallocate_pages` which does `libc::munmap` on central's copy

Meanwhile, micro also munmaps when the guest calls munmap. Both sides stay consistent.

**The only cost:** central holds onto the memory until the guest unmaps it. For a running program, this means central mirrors all file-backed mappings in its own address space. This is acceptable for now (central already mirrors all anonymous mappings too, via `allocate_pages`).

### Issue 2: Anonymous mmap EXEC_LOCAL

Currently, anonymous mmap goes through `dispatch_to_task` (central does real mmap) and returns the result directly. Micro never creates a matching mapping. This means:
- Central has the mapping at address X
- Guest code (running in micro) tries to access address X → SIGSEGV

**This is an existing bug for anonymous mmap too.** It works today only because the test program (`nolibc_hello`) doesn't use mmap. When libc.so.6 tries to mmap anonymous pages (e.g., for malloc), it will fail.

**Fix:** ALL mmap calls (anonymous and file-backed) should return EXEC_LOCAL so micro creates the actual mapping. Central still runs the shim to update PageManager state, but micro does the real mapping.

For anonymous mmap, no data transfer is needed — micro just does `mmap(MAP_ANONYMOUS)` locally.

### Issue 3: Address Selection

Central's PageManager picks the address (subject to ASLR, MAP_FIXED, etc.). Micro needs to map at the same address. We use `MAP_FIXED` in micro to ensure the address matches.

Risk: the chosen address might already be in use in micro's address space (by micro's own code/data segments, or the ring buffer). We assume this won't happen because:
- Central's PageManager respects `TASK_ADDR_MIN` and `TASK_ADDR_MAX`  
- Micro's own code/data are loaded at specific addresses that should be outside the guest address range
- The ring buffer is allocated separately

If this becomes a problem, we can add micro's reserved regions to central's `reserved_pages()`.

---

## Summary of Changes

### Files to modify:

1. **`litebox_platform_central/src/lib.rs`** — Implement GuestConstPtr and GuestMutPtr methods
2. **`litebox_central/src/server.rs`** — Special-case mmap to use EXEC_LOCAL + HAS_DATA for file-backed, EXEC_LOCAL for anonymous  
3. **`litebox_central/src/shmem.rs`** — Add `data_region_mut()` method
4. **`litebox_micro/src/local_exec.rs`** — Handle HAS_DATA flag for mmap
5. **`litebox_micro/src/handler.rs`** — Pass data region pointer to execute_locally (or access via global state)

### Files NOT modified (but considered):

- `litebox_ipc/src/ring.rs` — `HAS_DATA` flag already exists (`cq_flags::HAS_DATA = 1 << 1`)
- `litebox_ipc/src/messages.rs` — No new messages needed
- `litebox_common_linux/src/mm.rs` — Unchanged (do_mmap is generic over platform)
- `litebox_shim_linux/src/syscalls/mm.rs` — Unchanged (works once GuestMutPtr is fixed)

---

## Task Breakdown

### Task 1: Implement GuestConstPtr Methods

**Files:**
- Modify: `litebox_platform_central/src/lib.rs:235-258`
- Test: existing tests + new unit test

**Step 1: Write the failing test**

Add a test in `litebox_platform_central/src/lib.rs` that creates a `GuestConstPtr` from a known address and calls `read_at_offset` and `to_owned_slice`.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use litebox::platform::{RawConstPointer, RawMutPointer};

    #[test]
    fn guest_const_ptr_read_at_offset() {
        let value: u32 = 0xDEAD_BEEF;
        let ptr = GuestConstPtr::<u32>::from_usize(&value as *const u32 as usize);
        assert_eq!(ptr.read_at_offset(0), Some(0xDEAD_BEEF));
    }

    #[test]
    fn guest_const_ptr_to_owned_slice() {
        let data: [u8; 4] = [1, 2, 3, 4];
        let ptr = GuestConstPtr::<u8>::from_usize(data.as_ptr() as usize);
        let slice = ptr.to_owned_slice(4).unwrap();
        assert_eq!(&*slice, &[1, 2, 3, 4]);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p litebox_platform_central -- tests::guest_const_ptr`
Expected: FAIL with panic "CentralPlatform: guest pointers cannot be dereferenced"

**Step 3: Implement GuestConstPtr methods**

```rust
impl<T: FromBytes> RawConstPointer<T> for GuestConstPtr<T> {
    // ... as_usize and from_usize unchanged ...

    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        let ptr = self.addr as *const T;
        // SAFETY: The caller guarantees the address is valid in this process.
        // For CentralPlatform, this is true when the address came from allocate_pages.
        Some(unsafe { ptr.offset(count).read() })
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 || len == 0 {
            return None;
        }
        let ptr = self.addr as *const T;
        // SAFETY: The caller guarantees [ptr, ptr+len) is valid in this process.
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        Some(alloc::boxed::Box::from(slice))
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p litebox_platform_central -- tests::guest_const_ptr`
Expected: PASS

**Step 5: Commit**

```bash
git add litebox_platform_central/src/lib.rs
git commit -m "feat(central): implement GuestConstPtr pointer dereference methods"
```

### Task 2: Implement GuestMutPtr Methods

**Files:**
- Modify: `litebox_platform_central/src/lib.rs:284-323`
- Test: new unit tests

**Step 1: Write the failing test**

```rust
#[test]
fn guest_mut_ptr_write_at_offset() {
    let mut value: u32 = 0;
    let ptr = GuestMutPtr::<u32>::from_usize(&mut value as *mut u32 as usize);
    assert_eq!(ptr.write_at_offset(0, 42), Some(()));
    assert_eq!(value, 42);
}

#[test]
fn guest_mut_ptr_copy_from_slice() {
    let mut data = [0u8; 4];
    let ptr = GuestMutPtr::<u8>::from_usize(data.as_mut_ptr() as usize);
    assert_eq!(ptr.copy_from_slice(0, &[1, 2, 3, 4]), Some(()));
    assert_eq!(data, [1, 2, 3, 4]);
}

#[test]
fn guest_mut_ptr_mutate_subslice_with() {
    let mut data = [0u8; 4];
    let ptr = GuestMutPtr::<u8>::from_usize(data.as_mut_ptr() as usize);
    #[allow(deprecated)]
    let result = ptr.mutate_subslice_with(0..4, |slice| {
        slice.copy_from_slice(&[10, 20, 30, 40]);
        42
    });
    assert_eq!(result, Some(42));
    assert_eq!(data, [10, 20, 30, 40]);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p litebox_platform_central -- tests::guest_mut_ptr`
Expected: FAIL with panic "CentralPlatform: guest pointers cannot be written"

**Step 3: Implement GuestMutPtr methods**

```rust
impl<T: FromBytes> RawConstPointer<T> for GuestMutPtr<T> {
    // ... as_usize and from_usize unchanged ...

    fn read_at_offset(self, count: isize) -> Option<T> {
        if self.addr == 0 {
            return None;
        }
        let ptr = self.addr as *const T;
        Some(unsafe { ptr.offset(count).read() })
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        if self.addr == 0 || len == 0 {
            return None;
        }
        let ptr = self.addr as *const T;
        let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        Some(alloc::boxed::Box::from(slice))
    }
}

impl<T: FromBytes + IntoBytes> RawMutPointer<T> for GuestMutPtr<T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        if self.addr == 0 {
            return None;
        }
        let ptr = self.addr as *mut T;
        unsafe { ptr.offset(count).write(value) };
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
            core::ops::Bound::Excluded(&s) => s.checked_add(1)?,
            core::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            core::ops::Bound::Included(&e) => e.checked_add(1)?,
            core::ops::Bound::Excluded(&e) => e,
            core::ops::Bound::Unbounded => return None, // unbounded end not supported
        };
        if end < start {
            return None;
        }
        let len = usize::try_from(end - start).ok()?;
        let ptr = unsafe { (self.addr as *mut T).offset(start) };
        let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
        Some(f(slice))
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p litebox_platform_central -- tests::guest_mut_ptr`
Expected: PASS

**Step 5: Commit**

```bash
git add litebox_platform_central/src/lib.rs
git commit -m "feat(central): implement GuestMutPtr pointer dereference methods"
```

### Task 3: Add data_region_mut to SharedRegion

**Files:**
- Modify: `litebox_central/src/shmem.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn data_region_mut_is_writable() {
    let region = SharedRegion::new().expect("failed to create shared region");
    let data = region.data_region_mut();
    data[0] = 0xAB;
    assert_eq!(region.data_region()[0], 0xAB);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p litebox_central -- tests::data_region_mut_is_writable`
Expected: FAIL (method doesn't exist)

**Step 3: Implement data_region_mut**

```rust
/// Returns the data region as a mutable byte slice.
///
/// # Safety
///
/// The caller must ensure exclusive access to the data region.
pub fn data_region_mut(&self) -> &mut [u8] {
    unsafe {
        let base = self.ptr.as_ptr().add(self.layout.data_region_offset);
        std::slice::from_raw_parts_mut(base, self.layout.data_region_size)
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p litebox_central -- tests::data_region_mut`
Expected: PASS

**Step 5: Commit**

```bash
git add litebox_central/src/shmem.rs
git commit -m "feat(central): add data_region_mut to SharedRegion"
```

### Task 4: Update Central Server for mmap Handling

**Files:**
- Modify: `litebox_central/src/server.rs`

**Step 1: Add mmap special-case handling**

Before the `needs_local_exec` check, add mmap handling:

```rust
// Mmap handling: always goes through shim for PageManager tracking,
// then EXEC_LOCAL so micro creates the real mapping.
#[allow(clippy::cast_possible_truncation)]
if nr == libc::SYS_mmap as u32 {
    let flags = entry.args[3] as i32;
    let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
    let result = self.dispatch_to_task(entry.thread_slot, &mut regs);
    
    if result < 0 {
        // Shim returned error
        cq.result = result;
        return cq;
    }
    
    cq.result = result; // Address chosen by PageManager
    cq.flags = cq_flags::EXEC_LOCAL;
    
    // For file-backed mmap, also transfer the populated data
    if flags & libc::MAP_ANONYMOUS == 0 && result > 0 {
        let addr = result as usize;
        let len = entry.args[1] as usize;
        let data_region = self.region.data_region_mut();
        let copy_len = len.min(data_region.len());
        
        // SAFETY: addr is a valid pointer returned by allocate_pages in this process.
        // data_region is a valid mutable slice of the shared memory region.
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
    
    return cq;
}
```

**Step 2: Verify the build compiles**

Run: `cargo build -p litebox_central`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add litebox_central/src/server.rs
git commit -m "feat(central): route all mmap through shim + EXEC_LOCAL with data transfer"
```

### Task 5: Update Micro's Local Execution for mmap with HAS_DATA

**Files:**
- Modify: `litebox_micro/src/local_exec.rs`
- Modify: `litebox_micro/src/handler.rs` (pass data region info)

**Step 1: Update execute_locally signature**

The function needs access to the shared memory data region to copy file content. Add `ring_base` and `layout` parameters (or access via global state).

Since `MicroState` is already global and contains `ring_base` and `layout`, we can access it from within `execute_locally`:

```rust
nr if nr == libc::SYS_mmap as u32 => {
    if cq.flags & cq_flags::HAS_DATA != 0 {
        // File-backed mmap: central populated data in the shared memory data region.
        let map_addr = cq.result as usize;
        let map_len = args[1] as usize;
        let final_prot = args[2] as i32;
        let data_len = cq.data_len as usize;

        // 1. Create anonymous RW mapping at the address chosen by central's PageManager
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
            return -(unsafe { *libc::__errno_location() } as i64);
        }

        // 2. Copy file content from shared memory data region
        let micro = unsafe { &*crate::state::global_micro_state_ptr() };
        let data_src = unsafe {
            micro.ring_base
                .add(micro.layout.data_region_offset)
                .add(cq.data_offset as usize)
        };
        unsafe {
            core::ptr::copy_nonoverlapping(data_src, ptr as *mut u8, data_len);
        }

        // 3. Set final permissions (if different from PROT_READ|PROT_WRITE)
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
            unsafe {
                libc::mprotect(ptr, map_len, final_prot);
            }
        }

        map_addr as i64
    } else {
        // Anonymous mmap or other: execute the syscall directly
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                args[0] as usize, // Use the address from central's PageManager (cq.result)
                args[1] as usize,
                args[2] as i32,
                args[3] as i32,
                args[4] as i32,
                args[5] as i64,
            )
        }
    }
}
```

Wait — for anonymous mmap with EXEC_LOCAL, we need to handle this differently too. Currently micro just forwards the raw syscall args. But central's PageManager picked the address. Micro should map at that address.

For anonymous mmap:
- `cq.result` = address chosen by central's PageManager
- Micro should `mmap(cq.result, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)`

This is a behavior change from the current code which passes the original args through. Let me update:

```rust
nr if nr == libc::SYS_mmap as u32 => {
    let map_addr = cq.result as usize;
    let map_len = args[1] as usize;
    let final_prot = args[2] as i32;

    // Central's PageManager chose the address. Micro creates the real mapping there.
    let mmap_flags = if cq.flags & cq_flags::HAS_DATA != 0 {
        // File-backed: create anonymous RW, will copy data and mprotect later
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED
    } else {
        // Anonymous: use original flags but force the address
        (args[3] as i32 | libc::MAP_FIXED) & !libc::MAP_FIXED_NOREPLACE
    };

    let mmap_prot = if cq.flags & cq_flags::HAS_DATA != 0 {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        final_prot
    };

    let ptr = unsafe {
        libc::mmap(
            map_addr as *mut libc::c_void,
            map_len,
            mmap_prot,
            mmap_flags,
            -1, // Always anonymous fd in micro
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return -(unsafe { *libc::__errno_location() } as i64);
    }

    // For file-backed mmap, copy data from shared memory
    if cq.flags & cq_flags::HAS_DATA != 0 {
        let data_len = cq.data_len as usize;
        let micro = unsafe { &*crate::state::global_micro_state_ptr() };
        let data_src = unsafe {
            micro.ring_base
                .add(micro.layout.data_region_offset)
                .add(cq.data_offset as usize)
        };
        unsafe {
            core::ptr::copy_nonoverlapping(data_src, ptr as *mut u8, data_len);
        }

        // Set final permissions
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
            unsafe { libc::mprotect(ptr, map_len, final_prot); }
        }
    }

    map_addr as i64
}
```

**Step 2: Verify the build compiles**

Run: `cargo build -p litebox_micro`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add litebox_micro/src/local_exec.rs
git commit -m "feat(micro): handle file-backed mmap via HAS_DATA in EXEC_LOCAL path"
```

### Task 6: Handle mprotect/munmap/mremap Consistently

Since mmap now goes through central's shim AND micro creates the real mapping, mprotect/munmap/mremap also need to be consistent:

- **mprotect**: Currently dispatched through shim (central calls `libc::mprotect` on its local copy). Also needs EXEC_LOCAL so micro calls `mprotect` on its copy.
- **munmap**: Currently dispatched through shim. Also needs EXEC_LOCAL so micro calls `munmap`.
- **mremap**: Currently dispatched through shim. Also needs EXEC_LOCAL so micro calls `mremap`.

These are already in `local_exec.rs` as supported EXEC_LOCAL operations. We need to:
1. Add them to the mmap-like path in server.rs (dispatch through shim, then EXEC_LOCAL)
2. For EXEC_LOCAL mremap/munmap, micro uses the address from `cq.result`

**Step 1: Add mprotect/munmap/mremap/madvise/brk to the dual-dispatch path**

In `server.rs`, handle these memory management syscalls:

```rust
// Memory management syscalls: dispatch through shim for PageManager tracking,
// then EXEC_LOCAL so micro applies the change in its address space.
#[allow(clippy::cast_possible_truncation)]
if matches!(
    i64::from(nr),
    libc::SYS_mprotect | libc::SYS_munmap | libc::SYS_mremap | libc::SYS_madvise | libc::SYS_brk
) {
    let mut regs = crate::dispatch::sq_entry_to_ptregs(entry);
    cq.result = self.dispatch_to_task(entry.thread_slot, &mut regs);
    cq.flags = cq_flags::EXEC_LOCAL;
    return cq;
}
```

**Step 2: Update micro's EXEC_LOCAL for these syscalls**

For mprotect/munmap, micro already handles them. For mremap, micro needs to use `cq.result` as the new address (since central's PageManager chose it).

```rust
nr if nr == libc::SYS_mremap as u32 => {
    // Central's PageManager chose the new address
    let new_addr = cq.result as usize;
    if new_addr == args[0] as usize {
        // In-place growth (no move), use original args
        unsafe {
            libc::syscall(
                libc::SYS_mremap,
                args[0] as usize,
                args[1] as usize,
                args[2] as usize,
                args[3] as i32,
                args[4] as usize,
            )
        }
    } else {
        // Moved to new address, need MAP_FIXED equivalent
        unsafe {
            libc::syscall(
                libc::SYS_mremap,
                args[0] as usize,
                args[1] as usize,
                args[2] as usize,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                new_addr,
            )
        }
    }
}
```

**Step 3: Verify compilation**

Run: `cargo build -p litebox_central -p litebox_micro`

**Step 4: Commit**

```bash
git add litebox_central/src/server.rs litebox_micro/src/local_exec.rs
git commit -m "feat: dual-dispatch mprotect/munmap/mremap through shim + EXEC_LOCAL"
```

### Task 7: Integration Test

**Files:**
- Modify: `litebox_launcher/tests/integration.rs` (add file-backed mmap test if applicable)

**Step 1: Verify existing tests pass**

Run: `cargo test --workspace`
Expected: All existing tests pass (no regressions)

**Step 2: Write integration test for file-backed mmap (if test infrastructure supports it)**

This requires a test binary that does file-backed mmap and verifies the content. May need a new nolibc test binary.

**Step 3: Commit**

```bash
git commit -m "test: verify file-backed mmap works end-to-end"
```

---

## Future Work (Out of Scope)

1. **Large mapping support (> 4 MiB)**: Use memfd-based data transfer for mappings that exceed the data region
2. **Move remaining pointer-using syscalls to EXEC_LOCAL**: stat, pipe2, sigaction, etc.  
3. **Signal-safe SIGSEGV handler for GuestMutPtr**: Return `None` instead of crashing when accessing invalid addresses
4. **Shared memory mappings**: MAP_SHARED with write support
5. **CoW support**: Implement `try_allocate_cow_pages` for CentralPlatform using memfd + MAP_PRIVATE
