use pnet::packet;

pub struct PacketManifest<'p> {
    pub ethernet: packet::ethernet::EthernetPacket<'p>,
    pub ip: packet::ipv4::Ipv4Packet<'p>,
    pub tcp: packet::tcp::TcpPacket<'p>,
}
