// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{Platform, ShimFS, Task};

pub(crate) struct WaitState(litebox::event::wait::WaitState<Platform>);

impl WaitState {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }

    /// Returns the thread handle used to interrupt waits.
    pub(crate) fn thread_handle(&self) -> litebox::event::wait::ThreadHandle<Platform> {
        self.0.thread_handle()
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }

    /// Marks that the task has just returned from running guest code.
    pub(crate) fn enter_from_guest(&self) {
        self.wait_state.0.finish_running_guest();
    }

    /// Prepares to return to run guest code. Returns `false` if the task should
    /// exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.wait_state.0.prepare_to_run_guest(|| {
            use litebox::platform::SignalProvider as _;

            #[cfg(feature = "rr")]
            if self.global.rr_state.mode() == crate::rr::RRMode::Replay {
                // During replay, inject async signals from the trace instead
                // of draining host signals. Loop to handle multiple
                // consecutive signal events.
                while self.global.rr_state.peek_is_signal() {
                    match self.global.rr_state.replay_signal() {
                        Ok((signal_nr, _siginfo_bytes)) => {
                            // Reconstruct the signal and queue it (same as
                            // what take_pending_signals + queue_signals does).
                            let signal = litebox_common_linux::signal::Signal::try_from(signal_nr)
                                .expect("invalid signal number in trace");
                            self.queue_signals(signal);
                        }
                        Err(e) => panic!("replay signal error: {e:?}"),
                    }
                }
                // Process all pending signals (both trace-injected and
                // synchronous ones enqueued via handle_exception_request).
                self.process_signals(ctx);
                return !self.is_exiting();
            }

            self.global.platform.take_pending_signals(|signal| {
                // During recording, record each host-originated signal.
                #[cfg(feature = "rr")]
                if self.global.rr_state.mode() == crate::rr::RRMode::Record
                    && !crate::rr::is_synchronous_signal(signal)
                {
                    self.global
                        .rr_state
                        .record_signal(signal.as_i32(), alloc::vec![]);
                }
                self.queue_signals(signal);
            });
            self.check_alarm_deadline();
            self.process_signals(ctx);
            !self.is_exiting()
        })
    }
}

impl<FS: ShimFS> litebox::event::wait::CheckForInterrupt for Task<FS> {
    fn check_for_interrupt(&self) -> bool {
        use litebox::platform::SignalProvider as _;

        #[cfg(feature = "rr")]
        if self.global.rr_state.mode() == crate::rr::RRMode::Replay {
            // During replay, async signals come from the trace, not from the
            // host. Don't drain host signals — they would cause divergence.
            // But still check for pending synchronous signals and exit state.
            return self.is_exiting() || self.has_pending_signals();
        }

        self.global.platform.take_pending_signals(|sig| {
            self.queue_signals(sig);
        });
        self.check_alarm_deadline();
        self.is_exiting() || self.has_pending_signals()
    }
}
