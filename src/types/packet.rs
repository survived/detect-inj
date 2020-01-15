use std::net::IpAddr;
use pnet::packet;

pub struct PacketManifest<'p> {
    pub ethernet: packet::ethernet::EthernetPacket<'p>,
    pub ip: packet::ipv4::Ipv4Packet<'p>,
    pub tcp: packet::tcp::TcpPacket<'p>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Flow {
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
}

impl<'p> From<&PacketManifest<'p>> for Flow {
    fn from(packet: &PacketManifest<'p>) -> Self {
        let src = (IpAddr::V4(packet.ip.get_source()), packet.tcp.get_source());
        let dst = (IpAddr::V4(packet.ip.get_destination()), packet.tcp.get_destination());
        Self{ src, dst }
    }
}

impl Flow {
    pub fn reverse(mut self) -> Self {
        std::mem::swap(&mut self.src, &mut self.dst);
        self
    }
}

/// Used to identify packet sender side within Connection
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct SideIdentifier {
    client_flow: Flow,
    server_flow: Flow,
}

impl SideIdentifier {
    pub fn from_client_flow(client_flow: Flow) -> Self {
        Self{ client_flow, server_flow: client_flow.reverse() }
    }

    /// Determines which side has sent this packet.
    ///
    /// # Panic
    /// Panics if packet is sent by neither client nor server.
    pub fn identify(&self, packet: &PacketManifest) -> Side {
        if self.client_flow == Flow::from(packet) {
            Side::Client
        } else if self.server_flow == Flow::from(packet) {
            Side::Server
        } else {
            panic!("Unknown packet sender")
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Side {
    Client,
    Server,
}
