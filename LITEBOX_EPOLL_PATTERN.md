# LiteBox Epoll Notification Pattern for Pipes

This document shows the exact pattern used by pipes for epoll notification, which you can replicate for PTY devices.

---

## 1. POLLEE CREATION AND STORAGE

### Pollee Type and Location
**File:** `/workspace/litebox/litebox/src/event/polling.rs` (lines 24-26)

```rust
pub struct Pollee<Platform: RawSyncPrimitivesProvider> {
    subject: Subject<Events, Events, Platform>,
}
```

**Type Parameters:**
- `Platform: RawSyncPrimitivesProvider` - Required trait for synchronization primitives

### How Pollee is Created
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 282-295)

```rust
struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(rb: T) -> Self {
        Self {
            rb: Mutex::new(rb),
            pollee: Pollee::new(),
            is_shutdown: AtomicBool::new(false),
        }
    }
```

**Key Points:**
- `Pollee<Platform>` is created via `Pollee::new()` in `EndPointer::new()`
- Stored as `pollee: Pollee<Platform>` field
- Type parameter: `Pollee<Platform>` where Platform = `RawSyncPrimitivesProvider + TimeProvider`

---

## 2. NOTIFY_OBSERVERS() - EXACT CODE

### After Write Operations
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 410-442)

```rust
fn try_write(&self, buf: &[T]) -> Result<usize, TryOpError<PipeError>>
where
    T: Copy,
{
    if self.is_shutdown() {
        return Err(TryOpError::Other(PipeError::ThisEndShutdown));
    }
    if self.is_peer_shutdown() {
        return Err(TryOpError::Other(PipeError::PeerShutdown));
    }
    if buf.is_empty() {
        return Ok(0);
    }

    let write_len = {
        let mut rb = self.endpoint.rb.lock();
        let total_size = buf.len();
        if rb.vacant_len() < total_size && total_size <= self.atomic_slice_guarantee_size {
            // No sufficient space for an atomic write
            0
        } else {
            rb.push_slice(buf)
        }
    };
    if write_len > 0 {
        if let Some(peer) = self.peer.upgrade() {
            // NOTIFY ON WRITE: Signal data is available to read
            peer.endpoint.pollee.notify_observers(Events::IN);
        }
        Ok(write_len)
    } else {
        Err(TryOpError::TryAgain)
    }
}
```

### After Read Operations
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 529-550)

```rust
fn try_read(&self, buf: &mut [T]) -> Result<usize, TryOpError<PipeError>>
where
    T: Copy,
{
    if self.is_shutdown() {
        return Err(TryOpError::Other(PipeError::ThisEndShutdown));
    }
    if buf.is_empty() {
        return Ok(0);
    }

    let read_len = self.endpoint.rb.lock().pop_slice(buf);
    if read_len > 0 {
        if let Some(peer) = self.peer.upgrade() {
            // NOTIFY ON READ: Signal space is available to write
            peer.endpoint.pollee.notify_observers(Events::OUT);
        }
        Ok(read_len)
    } else {
        // ... more code
```

### On Shutdown/Errors
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 483-492)

```rust
impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> Drop for WriteEnd<Platform, T> {
    fn drop(&mut self) {
        self.shutdown();

        if let Some(peer) = self.peer.upgrade() {
            // when reading from a channel such as a pipe or a stream socket, this event
            // merely indicates that the peer closed its end of the channel.
            peer.endpoint.pollee.notify_observers(Events::HUP);
        }
    }
}
```

### Pattern Summary
```rust
// After data written: notify reader that data is available
pollee.notify_observers(Events::IN);

// After data read: notify writer that space is available
pollee.notify_observers(Events::OUT);

// On peer shutdown: notify with hangup event
pollee.notify_observers(Events::HUP);

// On error: notify with error event
pollee.notify_observers(Events::ERR);
```

---

## 3. IOPOLLABLE TRAIT IMPLEMENTATION

### IOPollable Trait Definition
**File:** `/workspace/litebox/litebox/src/event/mod.rs` (lines 37-51)

```rust
pub trait IOPollable {
    /// Register the `observer` to be notified whenever there are events within the `mask`.
    fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn observer::Observer<Events>>,
        mask: Events,
    );

    /// Get the current set of active events at this moment in time.
    fn check_io_events(&self) -> Events;
}
```

### Implementation for WriteEnd
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 465-481)

```rust
impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for WriteEnd<Platform, T> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let rb = self.endpoint.rb.lock();
        let mut events = Events::empty();
        if self.is_peer_shutdown() {
            events |= Events::ERR;
        }
        if !self.is_shutdown() && !rb.is_full() {
            events |= Events::OUT;
        }
        events
    }
}
```

### Implementation for ReadEnd
**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 502-518)

```rust
impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> IOPollable for ReadEnd<Platform, T> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let rb = self.endpoint.rb.lock();
        let mut events = Events::empty();
        if self.is_peer_shutdown() {
            events |= Events::HUP;
        }
        if !self.is_shutdown() && !rb.is_empty() {
            events |= Events::IN;
        }
        events
    }
}
```

### Key Implementation Points
- `register_observer()`: Delegates to `self.endpoint.pollee.register_observer()`
- `check_io_events()`: Returns current event status synchronously
  - For WriteEnd: Returns `OUT` if buffer not full, `ERR` if peer shutdown
  - For ReadEnd: Returns `IN` if data available, `HUP` if peer shutdown

---

## 4. ENDPOINTER STRUCT

**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 282-304)

```rust
struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider, T> {
    rb: Mutex<Platform, T>,
    pollee: Pollee<Platform>,
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider, T> EndPointer<Platform, T> {
    fn new(rb: T) -> Self {
        Self {
            rb: Mutex::new(rb),
            pollee: Pollee::new(),
            is_shutdown: AtomicBool::new(false),
        }
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }

    fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::Release);
    }
}
```

### Structure Breakdown
- `rb: Mutex<Platform, T>` - Protected data buffer (HeapProd for write end, HeapCons for read end)
- `pollee: Pollee<Platform>` - The observable entity for event notification
- `is_shutdown: AtomicBool` - Tracks whether this end is closed

---

## 5. EPOLL DESCRIPTOR VARIANTS

**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 37-44)

```rust
pub(crate) enum EpollDescriptor<FS: ShimFS> {
    Eventfd(Arc<super::eventfd::EventFile<Platform>>),
    Epoll(Arc<super::epoll::EpollFile<FS>>),
    File(Arc<crate::FileFd<FS>>),
    Socket(Arc<super::net::SocketFd>),
    Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
    Unix(Arc<crate::syscalls::unix::UnixSocket<FS>>),
}
```

### How Pipe FDs are Added to Epoll
**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 194-227)

```rust
fn add_interest(
    &self,
    global: &GlobalState<FS>,
    fd: u32,
    file: &EpollDescriptor<FS>,
    event: EpollEvent,
) -> Result<(), Errno> {
    let mut interests = self.interests.lock();
    let key = EpollEntryKey::new(fd, file);
    if let Some(entry) = interests.get(&key)
        && entry.desc.upgrade().is_some()
    {
        return Err(Errno::EEXIST);
    }

    let mask = Events::from_bits_truncate(event.events);
    let entry = EpollEntry::new(
        DescriptorRef::from(file),
        mask,
        EpollFlags::from_bits_truncate(event.events),
        event.data,
        self.ready.clone(),
    );
    // REGISTER: Register observer on the pollable with the entry as observer
    let events = file
        .poll(global, mask, Some(entry.weak_self.clone() as _))
        .ok_or(Errno::EBADF)?;
    // Add to ready list if already ready
    if !events.is_empty() {
        self.ready.push(&entry);
    }
    interests.insert(key, entry);
    Ok(())
}
```

### Pipe Variant Usage
**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 109-131)

```rust
let io_pollable: &dyn IOPollable = match self {
    EpollDescriptor::Eventfd(file) => file,
    EpollDescriptor::Epoll(_file) => unimplemented!(),
    EpollDescriptor::File(_file) => {
        // TODO: probably polling on stdio files, return dummy events for now
        return Some(Events::OUT & mask);
    }
    EpollDescriptor::Socket(fd) => {
        let proxy = match global.get_proxy(fd) {
            Ok(p) => p,
            Err(e) => {
                log_unsupported!("epoll poll with socket fd: {:?}", e);
                return None;
            }
        };
        return Some(poll(&proxy));
    }
    EpollDescriptor::Pipe(fd) => {
        // PIPE VARIANT: Uses with_iopollable to access the IOPollable impl
        return global.pipes.with_iopollable(fd, poll).ok();
    }
    EpollDescriptor::Unix(file) => file,
};
Some(poll(io_pollable))
```

### PTY Note
**No dedicated PTY variant exists** - it would need to be added as:
```rust
pub(crate) enum EpollDescriptor<FS: ShimFS> {
    // ... existing variants
    Pty(Arc<PTYFile>),  // NEW
}
```

---

## 6. DESCRIPTOR ENUM

**File:** `/workspace/litebox/litebox_shim_linux/src/lib.rs` (lines 715-759)

```rust
enum Descriptor<FS: ShimFS> {
    LiteBoxRawFd(usize),
    Eventfd {
        file: alloc::sync::Arc<syscalls::eventfd::EventFile<Platform>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Epoll {
        file: alloc::sync::Arc<syscalls::epoll::EpollFile<FS>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
    Unix {
        file: alloc::sync::Arc<syscalls::unix::UnixSocket<FS>>,
        close_on_exec: core::sync::atomic::AtomicBool,
    },
}
```

**Note:** Pipes use `Descriptor::LiteBoxRawFd(usize)` variant, not a dedicated variant.

---

## 7. PIPE REGISTRATION IN FD TABLE

**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 63-77)

```rust
pub fn create_pipe(
    &self,
    capacity: usize,
    flags: Flags,
    atomic_slice_guarantee_size: Option<NonZeroUsize>,
) -> (PipeFd<Platform>, PipeFd<Platform>) {
    let (sender, receiver) =
        new_pipe::<Platform, u8>(capacity, OFlags::from(flags), atomic_slice_guarantee_size);
    let sender = PipeEnd::Sender(sender);
    let receiver = PipeEnd::Receiver(receiver);
    let mut dt = self.litebox.descriptor_table_mut();
    // INSERT: PipeEnd enum gets inserted into descriptor table
    let sender = dt.insert(sender);
    let receiver = dt.insert(receiver);
    (sender, receiver)
}
```

### FD Enabled Subsystem Registration
**File:** `/workspace/litebox/litebox/src/pipes.rs` (last lines)

```rust
crate::fd::enable_fds_for_subsystem! {
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    Pipes<Platform>;
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    PipeEnd<Platform>;
    -> PipeFd<Platform>;
}
```

This macro:
1. Creates a wrapper `DescriptorEntry<PipeEnd<Platform>>`
2. Implements `FdEnabledSubsystem` for `Pipes<Platform>`
3. Implements `FdEnabledSubsystemEntry` for the wrapper
4. Implements `From<PipeEnd<Platform>>` conversion
5. Defines `PipeFd<Platform>` as a type alias for `TypedFd<Pipes<Platform>>`

### Descriptor Variant Used
Pipe read/write ends are registered as `Descriptor::LiteBoxRawFd(usize)` which stores:
- A `usize` index into the descriptor table
- The actual `PipeEnd<Platform>` is stored in `litebox.descriptor_table()`

---

## 8. EPOLL_WAIT AND NOTIFICATION CHAIN

### epoll_wait Implementation
**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 153-171)

```rust
pub(crate) fn wait(
    &self,
    global: &GlobalState<FS>,
    cx: &WaitContext<'_, Platform>,
    maxevents: usize,
) -> Result<Vec<EpollEvent>, WaitError> {
    let mut events = Vec::new();
    // WAIT: Use pollee to wait for IN event (entry added to ready list)
    match self.ready.pollee.wait(cx, false, Events::IN, || {
        self.ready.pop_multiple(global, maxevents, &mut events);
        if events.is_empty() {
            return Err(TryOpError::<Infallible>::TryAgain);
        }
        Ok(())
    }) {
        Ok(()) => Ok(events),
        Err(TryOpError::TryAgain) => unreachable!(),
        Err(TryOpError::WaitError(e)) => Err(e),
    }
}
```

### EpollEntry Observer Implementation
**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 372-376)

```rust
impl<FS: ShimFS> Observer<Events> for EpollEntry<FS> {
    fn on_events(&self, _events: &Events) {
        self.ready.push(self);
    }
}
```

### ReadySet notification chain
**File:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs` (lines 394-409)

```rust
fn push(&self, entry: &EpollEntry<FS>) {
    if !entry.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }

    if !entry
        .is_ready
        .swap(true, core::sync::atomic::Ordering::Relaxed)
    {
        let mut entries = self.entries.lock();
        entries.push_back(entry.weak_self.clone());
    }

    // NOTIFY: Signal epoll_wait that there are ready entries
    self.pollee.notify_observers(Events::IN);
}
```

### Complete Notification Chain
```
Pipe Data Written
  ↓
peer.endpoint.pollee.notify_observers(Events::IN)
  ↓
Calls Observer::on_events() on all registered observers
  ↓
EpollEntry::on_events() is called (EpollEntry is Observer<Events>)
  ↓
self.ready.push(self)  // Add entry to ready list
  ↓
ReadySet::push() calls pollee.notify_observers(Events::IN)
  ↓
Wakes up epoll_wait() which is waiting on ReadySet.pollee
  ↓
epoll_wait tries pop_multiple()
  ↓
Returns ready events to userspace
```

---

## 9. WITH_IOPOLLABLE HELPER

**File:** `/workspace/litebox/litebox/src/pipes.rs` (lines 167-177)

```rust
pub fn with_iopollable<R>(
    &self,
    fd: &PipeFd<Platform>,
    f: impl FnOnce(&dyn IOPollable) -> R,
) -> Result<R, errors::ClosedError> {
    let dt = self.litebox.descriptor_table();
    match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
        PipeEnd::Receiver(p) => Ok(f(p)),
        PipeEnd::Sender(p) => Ok(f(p)),
    }
}
```

This is used by epoll to get a `&dyn IOPollable` reference from a pipe FD for observer registration.

---

## SUMMARY TABLE

| Component | Location | Type Parameters |
|-----------|----------|-----------------|
| **Pollee** | event/polling.rs:24 | `<Platform: RawSyncPrimitivesProvider>` |
| **EndPointer** | pipes.rs:282 | `<Platform: RawSyncPrimitivesProvider + TimeProvider, T>` |
| **IOPollable::register_observer** | event/mod.rs:39 | - |
| **IOPollable::check_io_events** | event/mod.rs:46 | - |
| **WriteEnd impl IOPollable** | pipes.rs:465 | `<Platform: RawSyncPrimitivesProvider + TimeProvider, T>` |
| **ReadEnd impl IOPollable** | pipes.rs:502 | `<Platform: RawSyncPrimitivesProvider + TimeProvider, T>` |
| **EpollDescriptor::Pipe** | epoll.rs:42 | `Arc<litebox::pipes::PipeFd<Platform>>` |
| **EpollEntry** | epoll.rs:304 | `<FS: ShimFS>` |
| **ReadySet** | epoll.rs:378 | `<FS: ShimFS>` |
| **PipeFd** | pipes.rs macro | `TypedFd<Pipes<Platform>>` |

