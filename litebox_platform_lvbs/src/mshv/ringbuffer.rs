// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation and functions

use core::fmt;
use spin::{Mutex, Once};

pub struct RingBuffer {
    rb_va: *mut u8,
    write_offset: usize,
    size: usize,
}

impl RingBuffer {
    pub fn new(virt_addr: *mut u8, requested_size: usize) -> Self {
        RingBuffer {
            rb_va: virt_addr,
            write_offset: 0,
            size: requested_size,
        }
    }

    pub fn write(&mut self, buf: &[u8]) {
        // If the input buffer is longer than the ring buffer, fill the whole ring buffer with
        // the final [ring buffer size] values from the input buffer
        if buf.len() >= self.size {
            let single_slice = &buf[(buf.len() - self.size)..];
            unsafe {
                let _ = litebox::mm::exception_table::memcpy_fallible(
                    self.rb_va,
                    single_slice.as_ptr(),
                    self.size,
                );
            }
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let first_slice = &buf[..space_remaining];
            let wraparound_slice = &buf[space_remaining..];
            unsafe {
                let _ = litebox::mm::exception_table::memcpy_fallible(
                    self.rb_va.add(self.write_offset),
                    first_slice.as_ptr(),
                    first_slice.len(),
                );
                let _ = litebox::mm::exception_table::memcpy_fallible(
                    self.rb_va,
                    wraparound_slice.as_ptr(),
                    wraparound_slice.len(),
                );
            }
        } else {
            unsafe {
                let _ = litebox::mm::exception_table::memcpy_fallible(
                    self.rb_va.add(self.write_offset),
                    buf.as_ptr(),
                    buf.len(),
                );
            }
        }
        self.write_offset = (self.write_offset + buf.len()) % self.size;
    }
}

// SAFETY: RingBuffer is only accessed through a Mutex, and rb_va is a valid
// pointer to mapped memory that outlives the RingBuffer.
unsafe impl Send for RingBuffer {}

static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();
pub(crate) fn set_ringbuffer(va: *mut u8, size: usize) -> &'static Mutex<RingBuffer> {
    RINGBUFFER_ONCE.call_once(|| {
        let ring_buffer = RingBuffer::new(va, size);
        Mutex::new(ring_buffer)
    })
}

pub(crate) fn ringbuffer() -> Option<&'static Mutex<RingBuffer>> {
    RINGBUFFER_ONCE.get()
}

impl fmt::Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}
