// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker launcher.

use std::error::Error;
use std::ffi::OsString;
use std::io::Error as IoError;
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};
use std::sync::Arc;

use litebox_broker_core::socket::UnsupportedSocketProvider;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let control_pipe = unique_control_pipe_name();
    let control_listener = WindowsNamedPipeListener::bind(&control_pipe)?;
    let broker = BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()),
        Arc::new(UnsupportedSocketProvider),
    )?;

    let mut runner = Command::new(&args.runner)
        .arg("--unstable")
        .arg("--broker-control-pipe")
        .arg(&control_pipe)
        .args(&args.runner_arguments)
        .spawn()?;
    let runner_process_id = runner.id();
    let association_result = serve_runner(&broker, control_listener, &runner, runner_process_id);
    if association_result.is_err() {
        let _ = runner.kill();
    }
    let runner_status = runner.wait()?;
    association_result?;
    if !runner_status.success() {
        return Err(IoError::other(format!("runner exited with {runner_status}")).into());
    }
    Ok(())
}

fn serve_runner(
    broker: &BrokerCore,
    control_listener: WindowsNamedPipeListener,
    runner: &Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let control_channel = WindowsNamedPipeHostSetupChannel::accept_host_guaranteed(
        control_listener,
        runner_process_id,
    )?;
    let runner_process = runner.as_raw_handle();
    crate::serve_runner(
        broker,
        control_channel,
        WindowsSharedMemory::create,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
        WindowsNamedPipeHostSetupChannel::into_active,
    )
}

fn unique_control_pipe_name() -> OsString {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(r"\\.\pipe\litebox-broker-{process_id}-{nonce}").into()
}
