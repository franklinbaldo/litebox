# PTY Epoll Implementation Checklist

This checklist shows exactly what you need to do to replicate the pipe epoll notification pattern for PTY devices.

---

## Phase 1: Core PTY Data Structure

- [ ] Create PTY endpoint structure (similar to `EndPointer`)
  ```rust
  struct PTYEndpoint<Platform: RawSyncPrimitivesProvider + TimeProvider> {
      buffer: Mutex<Platform, RingBuffer>,
      pollee: Pollee<Platform>,
      is_shutdown: AtomicBool,
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:282-304`

- [ ] Create master and slave PTY structures (similar to `ReadEnd`/`WriteEnd`)
  ```rust
  struct PTYMaster<Platform: RawSyncPrimitivesProvider + TimeProvider> {
      endpoint: PTYEndpoint<Platform>,
      peer: Weak<PTYSlave<Platform>>,
      status: AtomicU32,
  }

  struct PTYSlave<Platform: RawSyncPrimitivesProvider + TimeProvider> {
      endpoint: PTYEndpoint<Platform>,
      peer: Weak<PTYMaster<Platform>>,
      status: AtomicU32,
  }
  ```

- [ ] Store `Pollee<Platform>` instance in endpoint
  - Type: `Pollee<Platform>` where `Platform: RawSyncPrimitivesProvider + TimeProvider`
  - Created via: `Pollee::new()`
  - Stored as: `self.endpoint.pollee`

---

## Phase 2: IOPollable Trait Implementation

- [ ] Implement `IOPollable` for `PTYMaster`
  ```rust
  impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for PTYMaster<Platform> {
      fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
          self.endpoint.pollee.register_observer(observer, filter);
      }

      fn check_io_events(&self) -> Events {
          let buffer = self.endpoint.buffer.lock();
          let mut events = Events::empty();
          
          if self.is_peer_shutdown() {
              events |= Events::HUP;
          }
          if !self.is_shutdown() && !buffer.is_empty() {
              events |= Events::IN;  // Data to read
          }
          if !self.is_shutdown() && !buffer.is_full() {
              events |= Events::OUT;  // Space to write
          }
          
          events
      }
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:465-481` (WriteEnd) and `502-518` (ReadEnd)

- [ ] Implement `IOPollable` for `PTYSlave` with similar logic

---

## Phase 3: Event Notification

- [ ] After master write to slave: notify slave readers
  ```rust
  fn pty_master_write(&self, buf: &[u8]) -> Result<usize, Error> {
      let write_len = {
          let mut buffer = self.endpoint.buffer.lock();
          buffer.push_slice(buf)
      };
      
      if write_len > 0 {
          if let Some(peer) = self.peer.upgrade() {
              // CRITICAL: Notify that data is ready
              peer.endpoint.pollee.notify_observers(Events::IN);
          }
          Ok(write_len)
      } else {
          Err(Error::WouldBlock)
      }
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:434-438`

- [ ] After slave write to master: notify master readers
  ```rust
  fn pty_slave_write(&self, buf: &[u8]) -> Result<usize, Error> {
      // ... similar to above, but notify master
      if write_len > 0 {
          if let Some(peer) = self.peer.upgrade() {
              peer.endpoint.pollee.notify_observers(Events::IN);
          }
      }
  }
  ```

- [ ] After master read from slave: notify slave writers
  ```rust
  fn pty_master_read(&self, buf: &mut [u8]) -> Result<usize, Error> {
      let read_len = self.endpoint.buffer.lock().pop_slice(buf);
      
      if read_len > 0 {
          if let Some(peer) = self.peer.upgrade() {
              // CRITICAL: Notify that write space is available
              peer.endpoint.pollee.notify_observers(Events::OUT);
          }
          Ok(read_len)
      } else {
          Err(Error::WouldBlock)
      }
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:543-544`

- [ ] On shutdown: notify with HUP or ERR
  ```rust
  impl<Platform> Drop for PTYMaster<Platform> {
      fn drop(&mut self) {
          self.shutdown();
          if let Some(peer) = self.peer.upgrade() {
              peer.endpoint.pollee.notify_observers(Events::HUP);
          }
      }
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:490`

---

## Phase 4: FD Subsystem Registration

- [ ] Create enum for PTY ends
  ```rust
  enum PTYEnd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
      Master(Arc<PTYMaster<Platform>>),
      Slave(Arc<PTYSlave<Platform>>),
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:197-200`

- [ ] Register subsystem using `enable_fds_for_subsystem!` macro
  ```rust
  crate::fd::enable_fds_for_subsystem! {
      @Platform: { RawSyncPrimitivesProvider + TimeProvider };
      PTYs<Platform>;
      @Platform: { RawSyncPrimitivesProvider + TimeProvider };
      PTYEnd<Platform>;
      -> PTYFd<Platform>;
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:593-599` (at end of file)

- [ ] Create `with_iopollable()` helper
  ```rust
  pub fn with_iopollable<R>(
      &self,
      fd: &PTYFd<Platform>,
      f: impl FnOnce(&dyn IOPollable) -> R,
  ) -> Result<R, ClosedError> {
      let dt = self.litebox.descriptor_table();
      match &dt.get_entry(fd).ok_or(ClosedError::ClosedFd)?.entry {
          PTYEnd::Master(p) => Ok(f(p)),
          PTYEnd::Slave(p) => Ok(f(p)),
      }
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:167-177`

---

## Phase 5: Epoll Integration

- [ ] Add PTY variant to `EpollDescriptor`
  ```rust
  pub(crate) enum EpollDescriptor<FS: ShimFS> {
      Eventfd(Arc<super::eventfd::EventFile<Platform>>),
      Epoll(Arc<super::epoll::EpollFile<FS>>),
      File(Arc<crate::FileFd<FS>>),
      Socket(Arc<super::net::SocketFd>),
      Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
      Pty(Arc<litebox::pty::PTYFd<Platform>>),  // NEW
      Unix(Arc<crate::syscalls::unix::UnixSocket<FS>>),
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs:37-44`

- [ ] Add PTY variant to `DescriptorRef`
  ```rust
  enum DescriptorRef<FS: ShimFS> {
      // ... existing variants
      Pty(Weak<litebox::pty::PTYFd<Platform>>),  // NEW
  }
  ```

- [ ] Implement `from()` and `upgrade()` for PTY
  ```rust
  impl<FS: ShimFS> DescriptorRef<FS> {
      fn from(value: &EpollDescriptor<FS>) -> Self {
          match value {
              // ... existing cases
              EpollDescriptor::Pty(pty) => Self::Pty(Arc::downgrade(pty)),
          }
      }

      fn upgrade(&self) -> Option<EpollDescriptor<FS>> {
          match self {
              // ... existing cases
              DescriptorRef::Pty(pty) => pty.upgrade().map(EpollDescriptor::Pty),
          }
      }
  }
  ```

- [ ] Add PTY polling in `EpollDescriptor::poll()`
  ```rust
  fn poll(&self, ...) -> Option<Events> {
      let poll = |iop: &dyn IOPollable| {
          if let Some(observer) = observer {
              iop.register_observer(observer, mask);
          }
          iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
      };
      
      let io_pollable: &dyn IOPollable = match self {
          // ... existing cases
          EpollDescriptor::Pty(fd) => {
              return global.ptys.with_iopollable(fd, poll).ok();
          }
      };
      Some(poll(io_pollable))
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox_shim_linux/src/syscalls/epoll.rs:109-131`

---

## Phase 6: Descriptor Table Integration

- [ ] Register PTY FD in descriptor table
  ```rust
  pub fn create_pty(&self, ...) -> Result<(PTYFd<Platform>, PTYFd<Platform>), Error> {
      let (master, slave) = new_pty::<Platform>(...);
      let master = PTYEnd::Master(master);
      let slave = PTYEnd::Slave(slave);
      let mut dt = self.litebox.descriptor_table_mut();
      let master = dt.insert(master);
      let slave = dt.insert(slave);
      Ok((master, slave))
  }
  ```
  
  **Reference:** `/workspace/litebox/litebox/src/pipes.rs:63-77`

- [ ] Add to `StrongFd` enum (in litebox_shim_linux)
  ```rust
  enum StrongFd<FS: ShimFS> {
      FileSystem(Arc<TypedFd<FS>>),
      Network(Arc<TypedFd<Network<Platform>>>),
      Pipes(Arc<TypedFd<Pipes<Platform>>>),
      Ptys(Arc<TypedFd<Ptys<Platform>>>),  // NEW
  }
  ```

- [ ] Add PTY case to `Descriptor::LiteBoxRawFd` conversion
  ```rust
  match StrongFd::<FS>::from_raw(files, *raw_fd)? {
      StrongFd::FileSystem(fd) => Ok(EpollDescriptor::File(fd)),
      StrongFd::Network(fd) => Ok(EpollDescriptor::Socket(fd)),
      StrongFd::Pipes(fd) => Ok(EpollDescriptor::Pipe(fd)),
      StrongFd::Ptys(fd) => Ok(EpollDescriptor::Pty(fd)),
  }
  ```

---

## Event Flow Verification

- [ ] Verify complete notification chain for PTY:

  ```
  User writes to PTY master
    ↓
  pty_master_write() → write data to buffer
    ↓
  peer.endpoint.pollee.notify_observers(Events::IN)
    ↓
  Calls EpollEntry::on_events() (EpollEntry implements Observer)
    ↓
  ready.push(entry)  → Add to ready list
    ↓
  ReadySet::push() → pollee.notify_observers(Events::IN)
    ↓
  Wakes up epoll_wait(master_epoll_fd)
    ↓
  Returns event to application
  ```

- [ ] Test each event type:
  - [ ] `Events::IN` - data available to read
  - [ ] `Events::OUT` - space available to write
  - [ ] `Events::HUP` - peer closed
  - [ ] `Events::ERR` - error condition

---

## Type Parameter Consistency Checklist

Use these exact type constraints everywhere:

```rust
Platform: RawSyncPrimitivesProvider + TimeProvider
```

This is required for:
- [ ] `PTYEndpoint<Platform>`
- [ ] `PTYMaster<Platform>`
- [ ] `PTYSlave<Platform>`
- [ ] `Pollee<Platform>`
- [ ] All IOPollable implementations

---

## File Locations to Update

1. **New file:** `litebox/src/pty.rs` (or similar)
   - Define PTYEndpoint, PTYMaster, PTYSlave, PTYEnd enum
   - Implement IOPollable for both ends
   - Implement subsystem registration macro
   
2. **Update:** `litebox/src/lib.rs` (or main module file)
   - Export PTY module
   - Register PTY subsystem

3. **Update:** `litebox_shim_linux/src/syscalls/epoll.rs`
   - Add `Pty` variant to `EpollDescriptor`
   - Add `Pty` variant to `DescriptorRef`
   - Add PTY case in `poll()` method
   - Update `try_from()` to handle PTY FDs

4. **Update:** `litebox_shim_linux/src/lib.rs`
   - Add `Ptys` variant to `StrongFd`
   - Add PTY case in `from_raw()` conversion
   - Add `Descriptor::LiteBoxRawFd` case for PTY

---

## Critical Implementation Notes

1. **Always use `Pollee::new()`** - Don't instantiate Subject directly
   
2. **Notify the peer's pollee, not own** - When master writes, notify slave's pollee:
   ```rust
   if let Some(peer) = self.peer.upgrade() {
       peer.endpoint.pollee.notify_observers(Events::IN);
   }
   ```

3. **Call notify after successful operation** - Only notify if data actually written/read:
   ```rust
   if write_len > 0 {
       peer.endpoint.pollee.notify_observers(Events::IN);
   }
   ```

4. **Use Events::ALWAYS_POLLED implicitly** - The `check_io_events()` doesn't need to mask it

5. **Register observer before checking events** - In `poll()`:
   ```rust
   if let Some(observer) = observer {
       iop.register_observer(observer, mask);
   }
   let events = iop.check_io_events() & (mask | Events::ALWAYS_POLLED);
   ```

6. **Use Arc for all shared resources** - PTYMaster and PTYSlave must be Arc-wrapped

7. **Use Weak for peer references** - Prevents circular Arc references causing memory leaks

