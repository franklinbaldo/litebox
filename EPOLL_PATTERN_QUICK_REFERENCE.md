# Epoll Notification Pattern - Quick Reference

## Core Pattern: Pollee Creation and Storage

```rust
// Step 1: Create endpoint with Pollee
struct YourEndpoint<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    buffer: Mutex<Platform, YourBuffer>,
    pollee: Pollee<Platform>,        // ← Key field for notifications
    is_shutdown: AtomicBool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> YourEndpoint<Platform> {
    fn new(buffer: YourBuffer) -> Self {
        Self {
            buffer: Mutex::new(buffer),
            pollee: Pollee::new(),      // ← Create with Pollee::new()
            is_shutdown: AtomicBool::new(false),
        }
    }
}
```

---

## Notification Pattern

```rust
// Pattern: Notify PEER's pollee after successful operation

// On write (notify reader)
if write_len > 0 {
    if let Some(peer) = self.peer.upgrade() {
        peer.endpoint.pollee.notify_observers(Events::IN);  // Data available
    }
}

// On read (notify writer)  
if read_len > 0 {
    if let Some(peer) = self.peer.upgrade() {
        peer.endpoint.pollee.notify_observers(Events::OUT); // Space available
    }
}

// On close
if let Some(peer) = self.peer.upgrade() {
    peer.endpoint.pollee.notify_observers(Events::HUP);    // Peer closed
}
```

---

## IOPollable Implementation Template

```rust
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for YourEndType<Platform> {
    fn register_observer(
        &self,
        observer: alloc::sync::Weak<dyn Observer<Events>>,
        filter: Events,
    ) {
        // Delegate to endpoint's pollee
        self.endpoint.pollee.register_observer(observer, filter);
    }

    fn check_io_events(&self) -> Events {
        let buffer = self.endpoint.buffer.lock();
        let mut events = Events::empty();
        
        // Check state and set appropriate events
        if self.is_peer_shutdown() {
            events |= Events::HUP;
        }
        
        if !self.is_shutdown() && !buffer.is_empty() {
            events |= Events::IN;  // Data to read
        }
        
        if !self.is_shutdown() && !buffer.is_full() {
            events |= Events::OUT; // Space to write
        }
        
        events
    }
}
```

---

## Event Types

| Event | Meaning | Trigger |
|-------|---------|---------|
| `Events::IN` | Data available to read | Call `notify_observers(Events::IN)` after write |
| `Events::OUT` | Space available to write | Call `notify_observers(Events::OUT)` after read |
| `Events::HUP` | Peer closed connection | Call `notify_observers(Events::HUP)` on shutdown |
| `Events::ERR` | Error condition | Call `notify_observers(Events::ERR)` on error |

---

## FD Subsystem Registration

```rust
// At end of your module file

crate::fd::enable_fds_for_subsystem! {
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    YourSystem<Platform>;              // Subsystem type
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    YourEndEnum<Platform>;             // Entry type (enum with Master/Slave)
    -> YourFd<Platform>;               // Alias for TypedFd<YourSystem>
}

// This generates:
// - DescriptorEntry wrapper
// - FdEnabledSubsystem impl for YourSystem
// - From<YourEndEnum> impl
// - Type alias YourFd<Platform> = TypedFd<YourSystem>
```

---

## Epoll Integration

### 1. Add to EpollDescriptor enum

```rust
pub(crate) enum EpollDescriptor<FS: ShimFS> {
    // ... existing variants
    Your(Arc<litebox::your::YourFd<Platform>>),
}
```

### 2. Add to DescriptorRef enum

```rust
enum DescriptorRef<FS: ShimFS> {
    // ... existing variants
    Your(Weak<litebox::your::YourFd<Platform>>),
}
```

### 3. Implement from() and upgrade()

```rust
impl<FS: ShimFS> DescriptorRef<FS> {
    fn from(value: &EpollDescriptor<FS>) -> Self {
        match value {
            // ... existing cases
            EpollDescriptor::Your(fd) => Self::Your(Arc::downgrade(fd)),
        }
    }

    fn upgrade(&self) -> Option<EpollDescriptor<FS>> {
        match self {
            // ... existing cases
            DescriptorRef::Your(fd) => fd.upgrade().map(EpollDescriptor::Your),
        }
    }
}
```

### 4. Add to poll() method

```rust
fn poll(&self, global: &GlobalState<FS>, mask: Events, 
        observer: Option<Weak<dyn Observer<Events>>>) -> Option<Events> {
    let poll = |iop: &dyn IOPollable| {
        if let Some(observer) = observer {
            iop.register_observer(observer, mask);
        }
        iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
    };
    
    match self {
        // ... existing cases
        EpollDescriptor::Your(fd) => {
            return global.your_system.with_iopollable(fd, poll).ok();
        }
    };
}
```

---

## Helper Method Template

```rust
pub fn with_iopollable<R>(
    &self,
    fd: &YourFd<Platform>,
    f: impl FnOnce(&dyn IOPollable) -> R,
) -> Result<R, errors::ClosedError> {
    let dt = self.litebox.descriptor_table();
    match &dt.get_entry(fd).ok_or(errors::ClosedError::ClosedFd)?.entry {
        YourEndEnum::MasterOrReader(e) => Ok(f(e)),
        YourEndEnum::SlaveOrWriter(e) => Ok(f(e)),
    }
}
```

---

## Complete Notification Flow

```
Your operation succeeds (write/read)
    ↓
Check if len > 0
    ↓
If YES: peer.endpoint.pollee.notify_observers(Events::{IN|OUT})
    ↓
notify_observers() calls on_events() on all registered Observer instances
    ↓
EpollEntry::on_events() is called (EpollEntry implements Observer<Events>)
    ↓
EpollEntry::on_events() calls self.ready.push(self)
    ↓
ReadySet::push() adds entry to ready list
    ↓
ReadySet::push() calls self.pollee.notify_observers(Events::IN)
    ↓
Wakes up epoll_wait() thread waiting on ReadySet.pollee
    ↓
epoll_wait() calls pop_multiple() and returns ready events to user
```

---

## Critical Points

1. **Type Parameters**: Always use `Platform: RawSyncPrimitivesProvider + TimeProvider`

2. **Notify Peer, Not Self**: After write, notify `peer.endpoint.pollee`, not `self.endpoint.pollee`

3. **Create with `Pollee::new()`**: Don't construct Subject directly

4. **Only Notify on Success**: Check length > 0 before calling notify_observers

5. **Arc + Weak Pattern**: 
   - Use `Arc<Your>` for shared ownership
   - Use `Weak<Your>` for peer references to avoid cycles

6. **Observer Registration Happens Here**:
   - `epoll_ctl(ADD)` → calls `EpollEntry::new()` → calls `file.poll(global, mask, Some(observer))`
   - The observer is the `EpollEntry` itself
   - Poll calls `iop.register_observer(observer, mask)`

7. **Never Block in notify_observers**: It's called from hot paths; keep it fast

---

## Common Events Mapping

```rust
// Read end
readable: !is_shutdown() && !buffer.is_empty()  → Events::IN
hangup:   is_peer_shutdown()                     → Events::HUP

// Write end  
writable: !is_shutdown() && !buffer.is_full()   → Events::OUT
error:    is_peer_shutdown() && is_shutdown()   → Events::ERR

// Always included implicitly: ERR, HUP, NVAL (via ALWAYS_POLLED)
```

