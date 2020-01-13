use std::convert::TryFrom;
use std::io;

use pnet::datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface, channel};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{self, Packet as _};

pub struct TcpIterator {
    send: Box<dyn DataLinkSender + 'static>,
    recv: Box<dyn DataLinkReceiver + 'static>,
}

pub enum Packet<'p> {
    Tcp(TcpPacketLayers<'p>),
    /// Represents a packet that wasn't recognized as TCP.
    FilteredOut(&'p [u8]),
}

pub struct TcpPacketLayers<'p> {
    pub ethernet: packet::ethernet::EthernetPacket<'p>,
    pub ip: packet::ipv4::Ipv4Packet<'p>,
    pub tcp: packet::tcp::TcpPacket<'p>,
}

impl TryFrom<&NetworkInterface> for TcpIterator {
    type Error = io::Error;
    fn try_from(interface: &NetworkInterface) -> io::Result<Self> {
        match channel(interface, Default::default())? {
            Ethernet(send, recv)
                => Ok(TcpIterator{ send, recv }),
            _ =>
                Err(io::Error::new(io::ErrorKind::Other, "cannot construct a channel")),
        }
    }
}

impl TcpIterator {
    fn parse_tcp_packet<'p>(ethernet_frame: &'p [u8]) -> Option<TcpPacketLayers<'p>> {
        // This will return None if the provided buffer is less
        // then the minimum required packet size
        let ethernet_packet = packet::ethernet::EthernetPacket::new(ethernet_frame)?;
        // TODO: support Ipv6
        if ethernet_packet.get_ethertype() != packet::ethernet::EtherTypes::Ipv4 {
            return None
        }

        let ethernet_payload = &ethernet_frame[ethernet_frame.len() - ethernet_packet.payload().len()..];
        let ipv4_packet = packet::ipv4::Ipv4Packet::new(ethernet_payload)?;
        if ipv4_packet.get_next_level_protocol() != packet::ip::IpNextHeaderProtocols::Tcp {
            return None
        }

        let ipv4_payload = &ethernet_payload[ethernet_payload.len() - ipv4_packet.payload().len() ..];
        let tcp_packet = packet::tcp::TcpPacket::new(ipv4_payload)?;
        Some(TcpPacketLayers {
            tcp: tcp_packet,
            ip: ipv4_packet,
            ethernet: ethernet_packet,
        })
    }

    pub fn next(&mut self) -> io::Result<Packet> {
        let ethernet_frame = self.recv.next()?;
        let parsed = Self::parse_tcp_packet(ethernet_frame);

        let result = self.send.build_and_send(1, ethernet_frame.len(),
                                              &mut |new_packet| {
                                                  new_packet.copy_from_slice(ethernet_frame);
                                              });
        match result {
            Some(Ok(())) => {}
            Some(Err(err)) => return Err(err),
            None => return Err(io::Error::new(io::ErrorKind::Other, "there is not sufficient capacity in the buffer")),
        }

        match parsed {
            Some(layers) => Ok(Packet::Tcp(layers)),
            None => Ok(Packet::FilteredOut(ethernet_frame))
        }
    }
}
