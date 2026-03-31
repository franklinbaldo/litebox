// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pre-allocated stack pool for vfork children.
//!
//! Each stack is a 64 KiB mmap'd anonymous region. Stacks are acquired
//! before `clone(CLONE_VM|CLONE_VFORK)` and released by the parent after
//! the clone returns (the parent is unblocked when the child calls execve
//! or _exit, at which point the child no longer uses the stack).

use crate::raw_syscall;

/// Size of each pooled stack (64 KiB).
const STACK_SIZE: usize = 64 * 1024;

/// Maximum number of pre-allocated stacks.
const INITIAL_POOL_SIZE: usize = 4;

/// A stack allocation: base address and size.
#[derive(Clone, Copy)]
pub struct PooledStack {
    pub base: *mut u8,
    pub size: usize,
}

// SAFETY: The raw pointer in `PooledStack` refers to a dedicated mmap'd
// region that is only accessed by a single thread at a time (the vfork
// parent owns it when not in use, the child owns it during clone).
unsafe impl Send for PooledStack {}

impl PooledStack {
    /// Returns the stack top (high address), suitable for clone's `child_stack` arg.
    pub fn top(&self) -> *mut u8 {
        unsafe { self.base.add(self.size) }
    }
}

/// Pool of pre-allocated stacks for vfork children.
///
/// Single-threaded access only (micro's syscall handler is single-threaded
/// per process). No synchronization needed.
pub struct StackPool {
    stacks: Vec<PooledStack>,
}

impl StackPool {
    pub fn new() -> Self {
        let mut stacks = Vec::with_capacity(INITIAL_POOL_SIZE);
        for _ in 0..INITIAL_POOL_SIZE {
            if let Some(s) = Self::alloc_stack() {
                stacks.push(s);
            }
        }
        Self { stacks }
    }

    pub fn acquire(&mut self) -> Option<PooledStack> {
        if let Some(s) = self.stacks.pop() {
            Some(s)
        } else {
            Self::alloc_stack()
        }
    }

    pub fn release(&mut self, stack: PooledStack) {
        self.stacks.push(stack);
    }

    fn alloc_stack() -> Option<PooledStack> {
        let ret = unsafe {
            raw_syscall::mmap(
                0,
                STACK_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw_syscall::is_error(ret) {
            None
        } else {
            Some(PooledStack {
                base: ret as *mut u8,
                size: STACK_SIZE,
            })
        }
    }
}
