use std::convert::TryFrom;
use std::net::IpAddr;
use std::io;

use pnet::datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface, channel};
use pnet::datalink::Channel::Ethernet;
use pdu;

use crate::types::{PacketManifest, IpLayer, TcpLayer, TcpFlags, Payload};

pub struct TcpIterator {
    send: Box<dyn DataLinkSender + 'static>,
    recv: Box<dyn DataLinkReceiver + 'static>,
}

pub enum Packet<'p> {
    Tcp(PacketManifest<'p>),
    /// Represents a packet that wasn't recognized as TCP.
    FilteredOut(&'p [u8]),
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
    pub fn next(&mut self) -> io::Result<Packet> {
        let ethernet_frame = self.recv.next()?;
        let parsed = Self::parse_ethernet(ethernet_frame);

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

    fn parse_ethernet(ethernet_frame: &[u8]) -> Option<PacketManifest> {
        let ethernet_pdu = pdu::EthernetPdu::new(ethernet_frame).ok()?;
        let inner = &ethernet_frame[ethernet_pdu.computed_ihl()..];
        Self::parse_ip(ethernet_pdu.ethertype(), inner)
    }
    fn parse_ip(ty: u16, buffer: &[u8]) -> Option<PacketManifest> {
        match ty {
            pdu::EtherType::IPV4 => {
                let ipv4_pdu = pdu::Ipv4Pdu::new(buffer).ok()?;
                let ip_layer = IpLayer {
                    src: IpAddr::V4(ipv4_pdu.source_address().into()),
                    dst: IpAddr::V4(ipv4_pdu.destination_address().into()),
                };
                let tcp_buffer = &buffer[ipv4_pdu.computed_ihl()..];
                Self::parse_tcp(ip_layer, tcp_buffer)
            }
            pdu::EtherType::IPV6 => {
                let ipv6_pdu = pdu::Ipv6Pdu::new(buffer).ok()?;
                let ip_layer = IpLayer {
                    src: IpAddr::V6(ipv6_pdu.source_address().into()),
                    dst: IpAddr::V6(ipv6_pdu.destination_address().into()),
                };
                let tcp_buffer = &buffer[ipv6_pdu.computed_ihl()..];
                Self::parse_tcp(ip_layer, tcp_buffer)
            }
            _ => return None
        }
    }
    fn parse_tcp(ip: IpLayer, buffer: &[u8]) -> Option<PacketManifest> {
        let tcp_pdu = pdu::TcpPdu::new(buffer).ok()?;
        let tcp_payload = Payload::from(&buffer[tcp_pdu.computed_data_offset()..]);
        Some(PacketManifest {
            ip,
            tcp: TcpLayer {
                src: tcp_pdu.source_port(),
                dst: tcp_pdu.destination_port(),
                ack: tcp_pdu.acknowledgement_number(),
                seq: tcp_pdu.sequence_number(),
                flags: TcpFlags {
                    syn: tcp_pdu.syn(),
                    ack: tcp_pdu.ack(),
                    fin: tcp_pdu.fin(),
                    rst: tcp_pdu.rst(),
                },
            },
            tcp_payload,
        })
    }
}
