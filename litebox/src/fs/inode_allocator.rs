// TODO DO NOT COMMIT

/// Sentinel `device_id` used by [`InodeAllocator::standalone`] for back-compat
/// with the previous hardcoded constant in standalone single-backend usage.
///
/// `b"Stnd".hex()`.
const STANDALONE_DEVICE_ID: u64 = 0x53746e64;

/// Allocator for `(device_id, inode)` pairs scoped to one backend instance.
///
/// Each backend instance constructs its allocator with a unique `device_id`
/// (or uses [`Self::standalone`] for single-backend back-compat). Inodes are
/// monotonically increasing; combined with the `device_id`, they're globally
/// unique.
#[derive(Debug)]
pub struct InodeAllocator {
    device_id: u64,
    counter: AtomicU64,
}

impl InodeAllocator {
    /// Construct an allocator for a specific `device_id`. The composer hands
    /// out unique `device_id`s per mounted backend.
    #[must_use]
    pub fn for_device(device_id: u64) -> Self {
        Self {
            device_id,
            counter: AtomicU64::new(0),
        }
    }

    /// Standalone allocator using the back-compat sentinel `device_id`.
    /// Suitable for single-backend usage that doesn't go through a composer.
    #[must_use]
    pub fn standalone() -> Self {
        Self::for_device(STANDALONE_DEVICE_ID)
    }

    /// The `device_id` assigned to this allocator.
    #[must_use]
    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Allocate a fresh `NodeInfo` for a new entry on this backend.
    #[must_use]
    pub fn next(&self) -> NodeInfo {
        let ino = self.counter.fetch_add(1, Ordering::Relaxed);
        NodeInfo {
            // The legacy `NodeInfo` uses `usize`; we cast through. On 64-bit
            // targets this is lossless. On 32-bit, the u64 device sentinel
            // values may truncate; the existing per-backend constants were
            // already `usize`, so this matches today's behavior shape.
            dev: ino_or_dev_to_usize(self.device_id),
            ino: ino_or_dev_to_usize(ino),
            rdev: None,
        }
    }
}

#[inline]
fn ino_or_dev_to_usize(v: u64) -> usize {
    // Truncates on 32-bit targets, matching legacy per-backend behavior
    // which used `usize` constants directly.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "intentional truncation on 32-bit targets, matching legacy"
    )]
    {
        v as usize
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------
