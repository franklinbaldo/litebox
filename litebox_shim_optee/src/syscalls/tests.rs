// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::syscalls::pta::{PseudoTa, PtaSystemCommandId};
use litebox_common_optee::{TeeParamType, UteeParams};
use litebox_platform_multiplex::{Platform, set_platform};

// Ensure we only init the platform once
static INIT_FUNC: spin::Once = spin::Once::new();

#[must_use]
#[cfg_attr(
    not(target_os = "linux"),
    expect(unused_variables, reason = "ignored parameter on non-linux platforms")
)]
pub(crate) fn init_platform() -> crate::Task {
    INIT_FUNC.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = Platform::new(None);

        #[cfg(not(target_os = "linux"))]
        let platform = Platform::new();

        #[cfg(target_os = "linux")]
        platform.initialize_boot_specific_kdf_support();

        set_platform(platform);
    });

    let shim_builder = crate::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
    shim_builder.build().0.new_test_task()
}

#[must_use]
pub(crate) fn init_platform_with_svn(ta_svn: u32) -> crate::Task {
    INIT_FUNC.call_once(|| {
        #[cfg(target_os = "linux")]
        let platform = Platform::new(None);

        #[cfg(not(target_os = "linux"))]
        let platform = Platform::new();

        #[cfg(target_os = "linux")]
        platform.initialize_boot_specific_kdf_support();

        set_platform(platform);
    });

    let shim_builder = crate::OpteeShimBuilder::new();
    let _litebox = shim_builder.litebox();
    shim_builder.build().0.new_test_task_with_svn(ta_svn)
}

#[test]
fn test_sys_log() {
    let task = init_platform();
    let result = task.sys_log(b"Hello! This is litebox_shim_optee.");
    assert!(result.is_ok());
}

#[test]
fn test_cryp_random_number_generate() {
    let task = init_platform();
    let mut buf = [0u8; 16];
    let result = task.sys_cryp_random_number_generate(&mut buf);
    assert!(result.is_ok() && buf != [0u8; 16]);
}

#[test]
fn test_sys_get_time_system_is_monotonic() {
    use litebox::platform::RawConstPointer as _;
    use litebox_common_optee::{TeeTime, TeeTimeCategory};

    let task = init_platform();

    let mut first = TeeTime::default();
    let first_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut first as usize);
    task.sys_get_time(TeeTimeCategory::System, first_ptr)
        .expect("system time should be supported");

    let mut second = TeeTime::default();
    let second_ptr = crate::UserMutPtr::<TeeTime>::from_usize(&raw mut second as usize);
    task.sys_get_time(TeeTimeCategory::System, second_ptr)
        .expect("system time should be supported");

    // `millis` is the sub-second remainder, so always in `0..1000`.
    assert!(first.millis < 1000 && second.millis < 1000);

    let first_ms = u64::from(first.seconds) * 1000 + u64::from(first.millis);
    let second_ms = u64::from(second.seconds) * 1000 + u64::from(second.millis);
    assert!(second_ms >= first_ms, "system time went backwards");
}

#[test]
fn test_derive_ta_svn_key_stack() {
    const KEY_SIZE: usize = 32;
    const STACK_SIZE: u32 = 8;

    let task = init_platform();
    let extra_data = [0xAAu8; 16];
    let mut key_buf = [0u8; KEY_SIZE];

    let mut params = UteeParams::new();
    params.set_type(0, TeeParamType::ValueInput).unwrap();
    params
        .set_values(0, KEY_SIZE as u64, u64::from(STACK_SIZE))
        .unwrap();
    params.set_type(1, TeeParamType::MemrefInput).unwrap();
    params
        .set_values(1, extra_data.as_ptr() as u64, extra_data.len() as u64)
        .unwrap();
    params.set_type(2, TeeParamType::MemrefOutput).unwrap();
    params
        .set_values(2, key_buf.as_mut_ptr() as u64, key_buf.len() as u64)
        .unwrap();
    params.set_type(3, TeeParamType::None).unwrap();

    let cmd_id = PtaSystemCommandId::DeriveTaSvnKeyStack as u32;

    // First call: actual derivation produces a non-trivial key for SVN 0.
    let _ = PseudoTa::System
        .invoke_command(&task, cmd_id, &mut params)
        .unwrap();
    let first = key_buf;
    assert_ne!(first, [0u8; KEY_SIZE], "derived key must not be all zeros");

    // Same inputs reproduce the same Key[0] (determinism).
    key_buf.fill(0);
    let _ = PseudoTa::System
        .invoke_command(&task, cmd_id, &mut params)
        .unwrap();
    assert_eq!(key_buf, first, "derivation must be deterministic");

    // Shorter chain must yield a different Key[0], proving the stack derivation
    // actually chains through all SVN levels rather than collapsing.
    params
        .set_values(0, KEY_SIZE as u64, u64::from(STACK_SIZE - 1))
        .unwrap();
    key_buf.fill(0);
    let _ = PseudoTa::System
        .invoke_command(&task, cmd_id, &mut params)
        .unwrap();
    assert_ne!(
        key_buf, first,
        "different chain depth must produce a different Key[0]"
    );
}

#[test]
fn test_derive_ta_svn_key_stack_allows_ta_svn_above_stack_size() {
    const KEY_SIZE: usize = 32;
    const STACK_SIZE: u32 = 2;
    const TA_SVN: u32 = 3;

    let task = init_platform_with_svn(TA_SVN);
    let extra_data = [0xAAu8; 16];
    let mut key_buf = [0u8; KEY_SIZE * (TA_SVN as usize + 1)];

    let mut params = UteeParams::new();
    params.set_type(0, TeeParamType::ValueInput).unwrap();
    params
        .set_values(0, KEY_SIZE as u64, u64::from(STACK_SIZE))
        .unwrap();
    params.set_type(1, TeeParamType::MemrefInput).unwrap();
    params
        .set_values(1, extra_data.as_ptr() as u64, extra_data.len() as u64)
        .unwrap();
    params.set_type(2, TeeParamType::MemrefOutput).unwrap();
    params
        .set_values(2, key_buf.as_mut_ptr() as u64, key_buf.len() as u64)
        .unwrap();
    params.set_type(3, TeeParamType::None).unwrap();

    let cmd_id = PtaSystemCommandId::DeriveTaSvnKeyStack as u32;
    let _ = PseudoTa::System
        .invoke_command(&task, cmd_id, &mut params)
        .unwrap();

    assert_ne!(&key_buf[..KEY_SIZE], &[0u8; KEY_SIZE]);
    assert_ne!(&key_buf[KEY_SIZE..KEY_SIZE * 2], &[0u8; KEY_SIZE]);
    assert_eq!(&key_buf[KEY_SIZE * 2..], &[0u8; KEY_SIZE * 2]);
}
