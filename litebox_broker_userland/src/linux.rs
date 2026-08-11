// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::io::{Error as IoError, Result as IoResult};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, CallerCredential, DestinationPortRange, DestinationRule,
    Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy, SocketPolicyError,
};
use litebox_broker_platform_linux_userland::LinuxSocketProvider;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
use litebox_broker_protocol::socket::{Ipv4Address, Port};
use litebox_broker_transport::channel::HostReceive;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingHostRequestSource, UnixControlRingHostResponseSink, UnixControlRingHostShutdown,
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    AllowedTcpDestination, HostAssociationShutdown, HostRequestSource, HostResponseSink,
    SETUP_TIMEOUT,
};

impl HostRequestSource for UnixControlRingHostRequestSource {
    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }
}

impl HostResponseSink for UnixControlRingHostResponseSink {
    fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostAssociationShutdown for UnixControlRingHostShutdown {
    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
    }
}

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let socket_dir = tempfile::Builder::new()
        .prefix("litebox-broker-userland-")
        .tempdir()?;
    let control_socket_path = socket_dir.path().join("broker.sock");
    let control_listener = UnixListener::bind(&control_socket_path)?;
    control_listener.set_nonblocking(true)?;
    let limits = BrokerCoreLimits::DEFAULT;
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
            .with_socket_policy(configured_socket_policy(&args.allow_tcp_destination)?),
        limits,
        Arc::new(LinuxSocketProvider::new(limits.max_sockets)?),
    )?;

    let mut runner_command = Command::new(&args.runner);
    runner_command
        .arg("--unstable")
        .arg("--broker-control-socket")
        .arg(&control_socket_path)
        .args(&args.runner_arguments);
    let mut runner = runner_command.spawn()?;
    let runner_process_id = runner.id();

    let association_result =
        serve_runner(&broker, &control_listener, &mut runner, runner_process_id);
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

fn configured_socket_policy(
    allowed_destinations: &[AllowedTcpDestination],
) -> Result<SocketPolicy, SocketPolicyError> {
    if allowed_destinations.is_empty() {
        return Ok(SocketPolicy::Ipv4Loopback);
    }
    let rules = allowed_destinations
        .iter()
        .map(|allowed| {
            DestinationRule::new(
                CallerCredential::HostGuaranteed,
                allowed.destination,
                allowed.ports,
            )
        })
        .collect::<Vec<_>>();
    let udp_loopback = DestinationRule::new(
        CallerCredential::HostGuaranteed,
        Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).expect("the IPv4 loopback CIDR is canonical"),
        DestinationPortRange::new(Port(1), Port(u16::MAX))
            .expect("the full nonzero UDP port range is valid"),
    );
    SocketPolicy::from_tcp_udp_destination_rules(&rules, &[udp_loopback])
}

fn serve_runner(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(runner, setup_deadline, "control", || {
        control_listener.accept().map(|(stream, _)| stream)
    })?;
    validate_peer_process(&control_stream, runner_process_id)?;
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    crate::serve_runner(
        broker,
        control_channel,
        MemfdSharedMemory::create,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_destination_arguments_replace_the_loopback_default() {
        assert_eq!(
            configured_socket_policy(&[]).unwrap(),
            SocketPolicy::Ipv4Loopback
        );

        let allowed = "0.0.0.0/0:80".parse::<AllowedTcpDestination>().unwrap();
        let policy = configured_socket_policy(&[allowed]).unwrap();
        let rules = policy.tcp_destination_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0],
            DestinationRule::new(
                CallerCredential::HostGuaranteed,
                allowed.destination,
                allowed.ports,
            )
        );
        assert_eq!(
            policy.udp_destination_rules().unwrap(),
            &[DestinationRule::new(
                CallerCredential::HostGuaranteed,
                Ipv4Cidr::new(Ipv4Address([127, 0, 0, 0]), 8).unwrap(),
                DestinationPortRange::new(Port(1), Port(u16::MAX)).unwrap(),
            )]
        );
    }
}
