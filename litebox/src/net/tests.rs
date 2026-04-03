// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use platform::mock::MockPlatform;

use super::*;

use core::net::SocketAddrV4;
use core::str::FromStr;

use crate::event::IOPollable;
use crate::net::socket_channel::{NetworkProxy, StreamSocketChannel};

extern crate std;

fn bidi_tcp_comms(mut network: Network<MockPlatform>, comms: fn(&mut Network<MockPlatform>)) {
    // Create a listening socket
    let listener_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");
    let listen_addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());

    network
        .bind(&listener_fd, &listen_addr)
        .expect("Failed to bind TCP socket");
    network
        .listen(&listener_fd, 1)
        .expect("Failed to listen on TCP socket");

    // Create a connecting socket
    let client_fd = network
        .socket(Protocol::Tcp)
        .expect("Failed to create TCP socket");
    let err = network
        .connect(&client_fd, &listen_addr, false)
        .unwrap_err();
    assert!(
        matches!(err, ConnectError::InProgress),
        "Expected InProgress error, got {err:?}",
    );

    comms(&mut network);

    // Accept the connection on the listening socket
    let server_fd = loop {
        match network.accept(&listener_fd, None) {
            Ok(fd) => break fd,
            Err(AcceptError::NoConnectionsReady) => {}
            Err(other) => panic!("Unexpected accept error: {other:?}"),
        }
    };

    // Send data from client to server
    let client_to_server_data = b"Hello from client!";
    let bytes_sent = network
        .send(&client_fd, client_to_server_data, SendFlags::empty(), None)
        .expect("Failed to send data");
    assert_eq!(bytes_sent, client_to_server_data.len());

    comms(&mut network);

    // Receive data on the server
    let mut server_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&server_fd, &mut server_buffer, ReceiveFlags::empty(), None)
        .expect("Failed to receive data");
    assert_eq!(&server_buffer[..bytes_received], client_to_server_data);

    // Send data from server to client
    let server_to_client_data = b"Hello from server!";
    let bytes_sent = network
        .send(&server_fd, server_to_client_data, SendFlags::empty(), None)
        .expect("Failed to send data");
    assert_eq!(bytes_sent, server_to_client_data.len());

    comms(&mut network);

    // Receive data on the client
    let mut client_buffer = [0u8; 1024];
    let bytes_received = network
        .receive(&client_fd, &mut client_buffer, ReceiveFlags::empty(), None)
        .expect("Failed to receive data");
    assert_eq!(&client_buffer[..bytes_received], server_to_client_data);

    network.close(&client_fd, CloseBehavior::Immediate).unwrap();
    network.close(&server_fd, CloseBehavior::Immediate).unwrap();
    network
        .close(&listener_fd, CloseBehavior::Immediate)
        .unwrap();
}

#[test]
fn test_bidirectional_tcp_communication_default() {
    let litebox = LiteBox::new(MockPlatform::new());
    let network = Network::new(&litebox);
    bidi_tcp_comms(network, |_| {});
}

#[test]
fn test_bidirectional_tcp_communication_manual() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);
    bidi_tcp_comms(network, |nw| {
        while nw.perform_platform_interaction().call_again_immediately() {}
    });
}

#[test]
fn test_bidirectional_tcp_communication_automatic() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Automatic);
    bidi_tcp_comms(network, |_| {});
}

#[test]
fn test_accept_keeps_listener_readable_when_more_connections_are_ready() {
    let litebox = LiteBox::new(MockPlatform::new());
    let mut network = Network::new(&litebox);
    network.set_platform_interaction(PlatformInteraction::Manual);

    let listener_fd = network.socket(Protocol::Tcp).unwrap();
    let listener_proxy = alloc::sync::Arc::new(NetworkProxy::Stream(StreamSocketChannel::new()));
    assert!(network.set_socket_proxy(&listener_fd, listener_proxy.clone()));
    let listen_addr = SocketAddr::V4(SocketAddrV4::from_str("10.0.0.2:8080").unwrap());
    network.bind(&listener_fd, &listen_addr).unwrap();
    network.listen(&listener_fd, 2).unwrap();

    let client1_fd = network.socket(Protocol::Tcp).unwrap();
    let client2_fd = network.socket(Protocol::Tcp).unwrap();
    assert!(matches!(
        network.connect(&client1_fd, &listen_addr, false),
        Err(ConnectError::InProgress)
    ));
    assert!(matches!(
        network.connect(&client2_fd, &listen_addr, false),
        Err(ConnectError::InProgress)
    ));

    for _ in 0..32 {
        while network
            .perform_platform_interaction()
            .call_again_immediately()
        {}
    }

    assert!(
        listener_proxy
            .check_io_events()
            .contains(crate::event::Events::IN)
    );

    let server1_fd = network.accept(&listener_fd, None).unwrap();
    let _ = server1_fd;

    assert!(
        listener_proxy
            .check_io_events()
            .contains(crate::event::Events::IN)
    );

    let server2_fd = network.accept(&listener_fd, None).unwrap();

    network
        .close(&client1_fd, CloseBehavior::Immediate)
        .unwrap();
    network
        .close(&client2_fd, CloseBehavior::Immediate)
        .unwrap();
    network
        .close(&server2_fd, CloseBehavior::Immediate)
        .unwrap();
    network
        .close(&listener_fd, CloseBehavior::Immediate)
        .unwrap();
}
