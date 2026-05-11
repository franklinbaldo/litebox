// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::Instant as _;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, TimeProvider as _};
use litebox_common_windows::nt_status::NtStatus;
use litebox_platform_multiplex::Platform;

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;

pub(crate) fn handle_nt_query_performance_counter(
    performance_counter: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i64>,
    performance_frequency: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<i64>,
    qpc_boot_instant: <Platform as litebox::platform::TimeProvider>::Instant,
) -> NtStatus {
    let elapsed = litebox_platform_multiplex::platform()
        .now()
        .duration_since(&qpc_boot_instant);
    let ticks =
        i64::try_from(core::cmp::min(elapsed.as_nanos(), i64::MAX as u128)).unwrap_or(i64::MAX);

    if performance_counter.write_at_offset(0, ticks).is_none() {
        return NtStatus::ACCESS_VIOLATION;
    }
    if performance_frequency.as_usize() != 0
        && performance_frequency
            .write_at_offset(0, QPC_FREQUENCY_HZ)
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }

    NtStatus::SUCCESS
}
