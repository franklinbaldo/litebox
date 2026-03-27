// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Micro-LiteBox: a lightweight, forkable in-process agent that intercepts
//! guest syscalls and proxies them to central LiteBox via shared-memory ring
//! buffer IPC.

pub mod fork;
pub mod handler;
pub mod local_exec;
pub mod state;
pub mod tls;
pub mod trampoline;

pub use state::micro_init;
pub use tls::micro_init_thread;
pub use trampoline::get_syscall_entry_point;
