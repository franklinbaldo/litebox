// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-style user stack setup.

use alloc::ffi::CString;
use alloc::vec::Vec;
use litebox::platform::{RawConstPointer as _, RawMutPointer};

use crate::MutPtr;

/// The stack for the macOS guest process.
///
/// Layout (stack grows downward, i.e. toward lower addresses):
/// ```text
/// position            content                     size (bytes)
/// ------------------------------------------------------------------------
/// stack pointer ->  [ argc = number of args ]     8
///                   [ argv[0] (pointer) ]         8   (program name)
///                   [ argv[..] (pointer) ]        8 * x
///                   [ argv[n] (pointer) ]         8   (= NULL)
///                   [ envp[0] (pointer) ]         8
///                   [ envp[..] (pointer) ]        8 * y
///                   [ envp[term] (pointer) ]      8   (= NULL)
///                   [ apple[0] (pointer) ]        8
///                   [ apple[term] (pointer) ]     8   (= NULL)
///                   [ padding ]                   0 - 16
///                   [ argument ASCIIZ strings ]   >= 0
///                   [ environment ASCIIZ str. ]   >= 0
///                   [ apple ASCIIZ strings ]      >= 0
///                   [ end marker ]                8   (= NULL)
///                   < bottom of stack >           0   (virtual)
/// ```
pub(super) struct UserStack {
    stack_top: MutPtr<u8>,
    #[expect(
        dead_code,
        reason = "retained for debugging and future guard page support"
    )]
    len: usize,
    pos: usize,
}

impl UserStack {
    const STACK_ALIGNMENT: usize = 16;

    pub(super) fn new(stack_top: MutPtr<u8>, len: usize) -> Option<Self> {
        if stack_top.as_usize() % Self::STACK_ALIGNMENT != 0 {
            return None;
        }
        if !len.is_multiple_of(Self::STACK_ALIGNMENT) {
            return None;
        }
        Some(Self {
            stack_top,
            len,
            pos: len,
        })
    }

    pub(super) fn get_cur_stack_top(&self) -> usize {
        self.stack_top.as_usize() + self.pos
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.pos = self.pos.checked_sub(bytes.len())?;
        self.stack_top.copy_from_slice(self.pos, bytes)?;
        Some(())
    }

    fn push_usize(&mut self, val: usize) -> Option<()> {
        self.push_bytes(&val.to_le_bytes())
    }

    fn push_cstring(&mut self, val: &CString) -> Option<()> {
        let bytes = val.as_bytes_with_nul();
        self.push_bytes(bytes)
    }

    fn push_cstrings(&mut self, vals: &[CString]) -> Option<Vec<usize>> {
        let mut offsets = Vec::with_capacity(vals.len());
        for val in vals {
            self.push_cstring(val)?;
            offsets.push(self.pos);
        }
        Some(offsets)
    }

    fn push_pointers(&mut self, offsets: Vec<usize>) -> Option<()> {
        // Write end marker (NULL)
        self.push_usize(0)?;
        let size = offsets.len().checked_mul(size_of::<usize>())?;
        self.pos = self.pos.checked_sub(size)?;
        let ptr: MutPtr<usize> = MutPtr::from_usize(self.stack_top.as_usize() + self.pos);
        for (i, p) in offsets.iter().enumerate() {
            let addr: usize = self.stack_top.as_usize() + *p;
            ptr.write_at_offset(i.cast_signed(), addr)?;
        }
        Some(())
    }

    /// Initialize the macOS-style stack.
    pub(super) fn init(&mut self, argv: Vec<CString>, env: Vec<CString>) -> Option<()> {
        self.init_with_apple(argv, env, Vec::new())
    }

    /// Initialize the macOS-style stack with apple entries.
    ///
    /// The apple array contains key-value strings (e.g. `executable_path=/path`)
    /// that dyld uses during initialization.
    pub(super) fn init_with_apple(
        &mut self,
        argv: Vec<CString>,
        env: Vec<CString>,
        apple: Vec<CString>,
    ) -> Option<()> {
        // End marker at bottom of stack (8 zero bytes)
        self.push_usize(0)?;

        // Push string data (stack grows downward)
        let apple_offsets = self.push_cstrings(&apple)?;
        let envp_offsets = self.push_cstrings(&env)?;
        let argvp_offsets = self.push_cstrings(&argv)?;

        // Ensure alignment
        let align_down = |pos: usize, alignment: usize| -> usize { pos & !(alignment - 1) };
        self.pos = align_down(self.pos, size_of::<usize>());

        // Calculate total items and ensure final alignment
        let len =
            (apple_offsets.len() + 1) + (envp_offsets.len() + 1) + (argvp_offsets.len() + 1) + 1; // argc
        let size = len * size_of::<usize>();
        let final_pos = self.pos.checked_sub(size)?;
        self.pos -= final_pos - align_down(final_pos, Self::STACK_ALIGNMENT);

        // Push apple[]
        self.push_pointers(apple_offsets)?;
        // Push envp
        self.push_pointers(envp_offsets)?;
        // Push argv
        self.push_pointers(argvp_offsets)?;
        // Push argc
        self.push_usize(argv.len())?;

        assert_eq!(self.pos, align_down(self.pos, Self::STACK_ALIGNMENT));
        Some(())
    }
}
