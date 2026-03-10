# LiteBox Epoll Notification Pattern Documentation

This directory contains comprehensive documentation for understanding and replicating the epoll notification pattern used by pipes for implementation in PTY devices.

## 📄 Documentation Files

### 1. **LITEBOX_EPOLL_PATTERN.md** (16 KB, 552 lines)
   - **Purpose**: Complete detailed reference of the actual implementation
   - **Content**:
     - Section 1: Pollee creation and storage with exact type parameters
     - Section 2: notify_observers() calls after write/read with full code
     - Section 3: IOPollable trait implementation for both WriteEnd and ReadEnd
     - Section 4: EndPointer struct definition and lifecycle
     - Section 5: EpollDescriptor enum variants and how pipes are added
     - Section 6: Descriptor enum in litebox_shim_linux
     - Section 7: Pipe registration in FD table and subsystem macro
     - Section 8: epoll_wait implementation and notification chain
     - Section 9: with_iopollable helper method
     - Summary table of all components
   - **Use This For**: Understanding the complete system architecture and finding exact code locations

### 2. **PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md** (12 KB, 400 lines)
   - **Purpose**: Step-by-step implementation guide for PTY devices
   - **Content**:
     - Phase 1: Core PTY data structure (endpoint, master, slave)
     - Phase 2: IOPollable trait implementation with templates
     - Phase 3: Event notification patterns (write, read, shutdown)
     - Phase 4: FD subsystem registration using the macro
     - Phase 5: Epoll integration (EpollDescriptor, DescriptorRef)
     - Phase 6: Descriptor table integration
     - Event flow verification
     - Type parameter consistency checklist
     - File locations to update
     - Critical implementation notes
   - **Use This For**: Implementing PTY epoll support step-by-step

### 3. **EPOLL_PATTERN_QUICK_REFERENCE.md** (7 KB, 266 lines)
   - **Purpose**: Quick lookup of key patterns and templates
   - **Content**:
     - Core pattern: Pollee creation and storage
     - Notification pattern with 3 examples (write, read, close)
     - IOPollable implementation template
     - Event types table
     - FD subsystem registration macro usage
     - Epoll integration (4 steps with code)
     - Helper method template
     - Complete notification flow diagram
     - Critical points checklist (7 items)
     - Event types mapping table
   - **Use This For**: Quick copy-paste templates and pattern verification

## 🎯 Quick Start Guide

### If you want to understand HOW pipes work:
1. Read: **EPOLL_PATTERN_QUICK_REFERENCE.md** (5 min)
2. Deep dive: **LITEBOX_EPOLL_PATTERN.md** sections 1-3 (15 min)

### If you want to implement PTY epoll support:
1. Start with: **PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md** Phase 1-3 (30 min)
2. Reference: **EPOLL_PATTERN_QUICK_REFERENCE.md** while coding (10 min per section)
3. Detail check: **LITEBOX_EPOLL_PATTERN.md** sections 5-8 (20 min)

### If you want to understand the notification flow:
1. Read: **EPOLL_PATTERN_QUICK_REFERENCE.md** "Complete Notification Flow" (5 min)
2. Deep dive: **LITEBOX_EPOLL_PATTERN.md** section 8 (10 min)
3. Implementation: **PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md** section "Event Flow Verification" (5 min)

## 📋 Key Patterns at a Glance

### Pattern 1: Pollee Creation
```rust
struct EndPointer<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    pollee: Pollee<Platform>,
}

impl EndPointer {
    fn new() -> Self {
        Self { pollee: Pollee::new() }
    }
}
```
**Location**: LITEBOX_EPOLL_PATTERN.md section 1 / QUICK_REFERENCE.md

### Pattern 2: Event Notification
```rust
// After data written, notify PEER's readers
if write_len > 0 {
    if let Some(peer) = self.peer.upgrade() {
        peer.endpoint.pollee.notify_observers(Events::IN);
    }
}
```
**Location**: LITEBOX_EPOLL_PATTERN.md section 2 / QUICK_REFERENCE.md

### Pattern 3: IOPollable Implementation
```rust
impl IOPollable for YourEnd {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, filter: Events) {
        self.endpoint.pollee.register_observer(observer, filter);
    }
    
    fn check_io_events(&self) -> Events {
        // Return current state as Events
    }
}
```
**Location**: LITEBOX_EPOLL_PATTERN.md section 3 / QUICK_REFERENCE.md

### Pattern 4: Subsystem Registration
```rust
crate::fd::enable_fds_for_subsystem! {
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    YourSystem<Platform>;
    @Platform: { RawSyncPrimitivesProvider + TimeProvider };
    YourEnd<Platform>;
    -> YourFd<Platform>;
}
```
**Location**: PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md Phase 4 / QUICK_REFERENCE.md

### Pattern 5: Epoll Integration
- Add variant to `EpollDescriptor` enum
- Add variant to `DescriptorRef` enum
- Implement `from()` and `upgrade()` methods
- Add case in `poll()` method

**Location**: PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md Phase 5 / QUICK_REFERENCE.md

## 🔍 File Location Reference

### Source Code Files Referenced

**LiteBox Core (litebox/src/):**
- `pipes.rs` - Pollee usage, notify_observers, IOPollable impl, EndPointer, PipeEnd enum
- `event/mod.rs` - IOPollable trait definition
- `event/polling.rs` - Pollee struct and implementation
- `fd/mod.rs` - enable_fds_for_subsystem macro, FdEnabledSubsystem trait

**Linux Shim (litebox_shim_linux/src/):**
- `syscalls/epoll.rs` - EpollDescriptor enum, EpollEntry, ReadySet, epoll_wait
- `lib.rs` - Descriptor enum, StrongFd enum

### Files You'll Need to Update for PTY

1. **New:** `litebox/src/pty.rs`
   - PTYEndpoint, PTYMaster, PTYSlave, PTYEnd enum
   - IOPollable implementations
   - Subsystem registration macro

2. **Update:** `litebox/src/lib.rs`
   - Export pty module

3. **Update:** `litebox_shim_linux/src/syscalls/epoll.rs`
   - Add Pty variant to EpollDescriptor
   - Add Pty variant to DescriptorRef
   - Update poll() method
   - Update try_from() method

4. **Update:** `litebox_shim_linux/src/lib.rs`
   - Add Ptys variant to StrongFd enum
   - Update from_raw() method

## 📊 Type Parameters Consistency

Always use this exact constraint everywhere:
```rust
Platform: RawSyncPrimitivesProvider + TimeProvider
```

This is required for:
- Pollee creation
- Endpoint structure
- Master/Slave structures
- All IOPollable implementations
- Subsystem registration

## ✅ Critical Implementation Checklist

- [ ] Pollee created with `Pollee::new()` in endpoint
- [ ] `notify_observers(Events::IN)` called after successful write
- [ ] `notify_observers(Events::OUT)` called after successful read
- [ ] `notify_observers(Events::HUP)` called on peer shutdown
- [ ] `register_observer()` delegates to endpoint.pollee
- [ ] `check_io_events()` returns current state without modifying
- [ ] IOPollable implemented for both master and slave
- [ ] FD subsystem macro used with correct type parameters
- [ ] `with_iopollable()` helper implemented
- [ ] EpollDescriptor variant added
- [ ] DescriptorRef variant added
- [ ] poll() method updated with your variant case
- [ ] StrongFd enum includes your subsystem
- [ ] Descriptor matching updated for your FD type

## 🔗 Related Concepts

- **Pollee**: Observable entity that notifies observers of events
- **Observer**: Registered listener that receives event notifications
- **IOPollable**: Trait for objects that can be polled for events
- **EpollDescriptor**: Union type representing different fd types for epoll
- **EpollEntry**: Observer implementation that bridges pollee → epoll_wait
- **ReadySet**: Queue of ready entries with its own pollee for epoll_wait

## 📝 Notes

1. **Pipes implementation is the reference**: The pipe implementation in litebox/src/pipes.rs is the canonical example of the pattern
2. **Type safety**: The macro-generated code ensures type safety through FdEnabledSubsystem trait
3. **Notification chain**: Notifications flow from pollee → Observer → EpollEntry → ReadySet.pollee → epoll_wait
4. **No blocking**: notify_observers() is non-blocking and very fast
5. **Weak references prevent cycles**: Use Arc for owned data, Weak for peer references

## 🚀 Next Steps

1. **Read**: EPOLL_PATTERN_QUICK_REFERENCE.md (complete overview)
2. **Study**: LITEBOX_EPOLL_PATTERN.md section 1-4 (understand the pattern)
3. **Plan**: Prepare your PTY structure using the template
4. **Check**: PTY_EPOLL_IMPLEMENTATION_CHECKLIST.md Phase 1-3
5. **Implement**: Phases 4-6 using QUICK_REFERENCE.md for code
6. **Verify**: Test complete notification flow with Phase 6 event flow verification

---

**Last Updated**: 2024-03-09
**Reference Implementation**: LiteBox Pipes (litebox/src/pipes.rs)
**Target Implementation**: PTY Devices with Epoll Support
