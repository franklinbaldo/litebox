// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::error::Error;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, CallerCredential, DestinationPortRange, DestinationRule,
    Ipv4Cidr, ObjectRights, PolicyEngine, SocketPolicy, SocketPolicyError,
};
use litebox_broker_platform_linux_userland::LinuxSocketProvider;
use litebox_broker_protocol::socket::{Ipv4Address, Port};
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AllowedTcpDestination {
    destination: Ipv4Cidr,
    ports: DestinationPortRange,
}

impl FromStr for AllowedTcpDestination {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (cidr, ports) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected CIDR:PORT or CIDR:START-END".to_owned())?;
        let (network, prefix_length) = cidr
            .split_once('/')
            .ok_or_else(|| "destination must include an IPv4 CIDR prefix".to_owned())?;
        let network = network
            .parse::<Ipv4Addr>()
            .map_err(|error| format!("invalid IPv4 network: {error}"))?;
        let prefix_length = prefix_length
            .parse::<u8>()
            .map_err(|error| format!("invalid IPv4 prefix length: {error}"))?;
        let destination =
            Ipv4Cidr::new(Ipv4Address(network.octets()), prefix_length).ok_or_else(|| {
                "IPv4 CIDR must have a valid prefix and canonical network address".to_owned()
            })?;

        let (start, end) = ports
            .split_once('-')
            .map_or((ports, ports), |(start, end)| (start, end));
        let start = start
            .parse::<u16>()
            .map_err(|error| format!("invalid TCP port: {error}"))?;
        let end = end
            .parse::<u16>()
            .map_err(|error| format!("invalid TCP port: {error}"))?;
        let ports = DestinationPortRange::new(Port(start), Port(end))
            .ok_or_else(|| "TCP port range must be ordered and exclude port zero".to_owned())?;

        Ok(Self { destination, ports })
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
    let control_stream = accept_runner_stream(
        control_listener,
        runner,
        runner_process_id,
        setup_deadline,
        "control",
    )?;
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

fn accept_runner_stream(
    listener: &UnixListener,
    runner: &mut Child,
    runner_process_id: u32,
    deadline: Instant,
    channel_name: &'static str,
) -> IoResult<UnixStream> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
            ));
        }
        if let Some(status) = runner.try_wait()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner exited with {status} before connecting its {channel_name} channel"),
            ));
        }

        match listener.accept() {
            Ok((stream, _)) => {
                validate_peer_process(&stream, runner_process_id)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_destination_argument_parses_canonical_cidr_and_ports() {
        let allowed = "203.0.113.0/24:443-444"
            .parse::<AllowedTcpDestination>()
            .unwrap();

        assert_eq!(
            allowed,
            AllowedTcpDestination {
                destination: Ipv4Cidr::new(Ipv4Address([203, 0, 113, 0]), 24).unwrap(),
                ports: DestinationPortRange::new(Port(443), Port(444)).unwrap(),
            }
        );
        assert!(
            "203.0.113.1/24:443"
                .parse::<AllowedTcpDestination>()
                .is_err()
        );
        assert!("203.0.113.0/24:0".parse::<AllowedTcpDestination>().is_err());
    }

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
