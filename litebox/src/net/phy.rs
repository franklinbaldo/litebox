// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection to the physical (i.e., "lower") side for networking.
//!
//! When the device medium is "Ip" (no Ethernet framing), transmitted packets
//! are raw IPv4/IPv6 datagrams.  We inspect the IPv4 destination address and
//! short-circuit packets addressed to the interface's own IP back into the
//! receive path (loopback).  Without this, self-connections (e.g. a guest
//! binding to 10.0.0.2 and connecting to 10.0.0.2) would send the SYN out
//! the TUN device where the host kernel has no reason to reflect it back.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

pub(crate) struct Device<Platform: platform::IPInterfaceProvider + 'static> {
    pub(crate) platform: &'static Platform,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
    /// Packets addressed to the interface's own IP are looped back here
    /// instead of being sent out through the platform.
    loopback_queue: VecDeque<Vec<u8>>,
    /// The interface's own IPv4 address, used to detect loopback packets.
    interface_ip: Ipv4Addr,
}

impl<Platform: platform::IPInterfaceProvider> Device<Platform> {
    pub(crate) fn new(platform: &'static Platform, interface_ip: Ipv4Addr) -> Self {
        Self {
            platform,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
            loopback_queue: VecDeque::new(),
            interface_ip,
        }
    }
}

/// Check whether a raw IP packet is an IPv4 datagram whose destination
/// address matches `interface_ip`.
fn is_self_addressed(packet: &[u8], interface_ip: Ipv4Addr) -> bool {
    // IPv4: version nibble == 4, destination address at bytes 16..20.
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        dst == interface_ip
    } else {
        false
    }
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::Device for Device<Platform> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, Platform>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Check loopback queue first — these are packets we sent to ourselves.
        if let Some(packet) = self.loopback_queue.pop_front() {
            let len = packet.len().min(self.receive_buffer.len());
            self.receive_buffer[..len].copy_from_slice(&packet[..len]);
            return Some((
                RxToken {
                    buffer: &self.receive_buffer[..len],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback_queue: &mut self.loopback_queue,
                    interface_ip: self.interface_ip,
                },
            ));
        }

        // Then check the platform (TUN device).
        match self.platform.receive_ip_packet(&mut self.receive_buffer) {
            Ok(size) => Some((
                RxToken {
                    buffer: &self.receive_buffer[..size],
                },
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback_queue: &mut self.loopback_queue,
                    interface_ip: self.interface_ip,
                },
            )),
            Err(platform::ReceiveError::WouldBlock) => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            buffer: &mut self.send_buffer,
            loopback_queue: &mut self.loopback_queue,
            interface_ip: self.interface_ip,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

pub(crate) struct RxToken<'a> {
    buffer: &'a [u8],
}

impl smoltcp::phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.buffer)
    }
}

pub(crate) struct TxToken<'a, Platform: platform::IPInterfaceProvider> {
    platform: &'a Platform,
    buffer: &'a mut [u8],
    loopback_queue: &'a mut VecDeque<Vec<u8>>,
    interface_ip: Ipv4Addr,
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::TxToken for TxToken<'_, Platform> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);
        if is_self_addressed(packet, self.interface_ip) {
            // Loopback: queue the packet for the next receive() call.
            self.loopback_queue.push_back(packet.to_vec());
        } else {
            self.platform
                .send_ip_packet(packet)
                .expect("Sending IP packet failed");
        }
        res
    }
}
