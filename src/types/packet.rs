use std::net::IpAddr;
use pnet::packet;

pub struct PacketManifest<'p> {
    pub ethernet: packet::ethernet::EthernetPacket<'p>,
    pub ip: packet::ipv4::Ipv4Packet<'p>,
    pub tcp: packet::tcp::TcpPacket<'p>,
}

/// Used to identify packet sender side within Connection
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct SideIdentifier {
    client: (IpAddr, u16),
    server: (IpAddr, u16),
}

impl SideIdentifier {
    pub fn new(client: (IpAddr, u16), server: (IpAddr, u16)) -> Self {
        Self{ client, server }
    }

    /// Determines which side has sent this packet.
    ///
    /// # Panic
    /// Panics if packet is sent by neither client nor server.
    pub fn identify(&self, packet: &PacketManifest) -> Side {
        if IpAddr::V4(packet.ip.get_source()) == self.client.0 && IpAddr::V4(packet.ip.get_destination()) == self.server.0
            && packet.tcp.get_source() == self.client.1 && packet.tcp.get_destination() == self.server.1
        {
            Side::Client
        } else if IpAddr::V4(packet.ip.get_source()) == self.server.0 && IpAddr::V4(packet.ip.get_destination()) == self.client.0
            && packet.tcp.get_source() == self.server.1 && packet.tcp.get_destination() == self.client.1
        {
            Side::Server
        } else {
            panic!("Unknown packet sender")
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum Side {
    Client,
    Server,
}
