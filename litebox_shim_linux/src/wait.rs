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
                // Ensure this thread holds the run token before returning
                // to guest code. The token was released after the previous
                // syscall and the coordinator scheduled us based on the
                // trace.
                if let Some(coord) = self.global.rr_state.coordinator()
                    && !coord.acquire_token(self.rr_tid_i32())
                {
                    // Coordinator shut down — exit this thread.
                    return false;
                }

                // During replay, inject async signals from the trace instead
                // of draining host signals. Loop to handle multiple
                // consecutive signal events.
                while self.global.rr_state.peek_is_signal() {
                    match self.global.rr_state.replay_signal() {
                        Ok((signal_nr, _siginfo_bytes)) => {
                            let signal = litebox_common_linux::signal::Signal::try_from(signal_nr)
                                .expect("invalid signal number in trace");
                            // Only inject if the signal is not already in a
                            // pending set. Structural syscalls like
                            // kill/tgkill/tkill queue signals directly via
                            // send_signal (thread-level pending), while
                            // queue_signals uses send_shared_signal
                            // (process-level shared_pending). Without this
                            // check, both copies would be delivered — once from
                            // each queue — causing spurious double delivery.
                            if !self.pending_signal_set().contains(signal) {
                                self.queue_signals(signal);
                            }
                        }
                        Err(e) => panic!("replay signal error: {e:?}"),
                    }
                }
                // Process all pending signals (both trace-injected and
                // synchronous ones enqueued via handle_exception_request).
                self.process_signals(ctx);
                return !self.is_exiting();
            }

            #[cfg(feature = "rr")]
            if self.global.rr_state.mode() == crate::rr::RRMode::Record {
                // Ensure this thread holds the run token before returning
                // to guest code.
                if let Some(coord) = self.global.rr_state.coordinator()
                    && !coord.acquire_token(self.rr_tid_i32())
                {
                    return false;
                }
            }

            self.global.platform.take_pending_signals(|signal| {
                self.queue_signals(signal);
            });
            self.check_alarm_deadline();

            // During recording, record all pending async signals as delivery
            // events. This is done AFTER take_pending_signals and
            // check_alarm_deadline (so all signal sources are captured) and
            // BEFORE process_signals (so events appear in the trace before the
            // rt_sigreturn that the handler will issue). This also captures
            // signals that were queued during check_for_interrupt inside a
            // blocking syscall (e.g., SIGALRM interrupting nanosleep).
            #[cfg(feature = "rr")]
            if self.global.rr_state.mode() == crate::rr::RRMode::Record {
                let tid = self.rr_tid();
                for signal in self.pending_signal_set() {
                    if !crate::rr::is_synchronous_signal(signal) {
                        self.global
                            .rr_state
                            .record_signal(signal.as_i32(), alloc::vec![], tid);
                    }
                }
            }

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
