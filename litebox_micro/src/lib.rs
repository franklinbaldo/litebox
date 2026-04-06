// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Micro-LiteBox: a lightweight, forkable in-process agent that intercepts
//! guest syscalls and proxies them to central LiteBox via shared-memory ring
//! buffer IPC.

pub mod execve;
pub mod fork;
pub mod handler;
pub mod local_exec;
#[allow(clippy::missing_safety_doc, clippy::cast_sign_loss)]
pub mod raw_syscall;
pub mod state;
pub mod thread;
pub mod tls;
pub mod trampoline;

pub use state::micro_init;
pub use tls::micro_init_thread;
pub use trampoline::get_syscall_entry_point;
