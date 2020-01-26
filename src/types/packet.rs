use std::borrow::Cow;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::ops;

use pnet::packet;

use crate::types::Sequence;

/// Represents information about TCP packet that matters for injections detection.
#[derive(Debug)]
pub struct PacketManifest<'p> {
    pub ip: IpLayer,
    pub tcp: TcpLayer,
    pub tcp_payload: Payload<'p>,
}

impl<'p> PacketManifest<'p> {
    pub fn cloned(&self) -> PacketManifest<'static> {
        let tcp_payload = Payload(Cow::Owned(self.tcp_payload.0.clone().into_owned()));
        PacketManifest {
            ip: self.ip,
            tcp: self.tcp,
            tcp_payload,
        }
    }

    /// Splits packet's payload at given position.
    ///
    /// Resulted package payloads are: `[package.tcp.seq, seq_no]`,
    /// `(seq_no, package.tcp.seq + package.tcp_payload.len()`. The second's package sequence number
    /// is set to `seq_no`.
    ///
    /// # Panic
    /// Panics if `seq_no` is out of package range.
    pub fn split_at(self, seq_no: Sequence) -> (PacketManifest<'p>, PacketManifest<'p>) {
        let ind = match usize::try_from(seq_no - Sequence::from(self.tcp.seq)) {
            Ok(n) if n < self.tcp_payload.len() => n,
            _ => panic!("seq_no is out of package range"),
        };
        match self.tcp_payload.0 {
            Cow::Owned(mut payload) => {
                let second_payload = payload.split_off(ind+1);
                let first_package = PacketManifest {
                    ip: self.ip,
                    tcp: self.tcp,
                    tcp_payload: Payload(Cow::Owned(payload)),
                };
                let second_package = PacketManifest {
                    ip: self.ip,
                    tcp: TcpLayer {
                        seq: seq_no.into(),
                        ..self.tcp
                    },
                    tcp_payload: Payload(Cow::Owned(second_payload)),
                };
                (first_package, second_package)
            }
            Cow::Borrowed(payload) => {
                let (first_payload, second_payload) = payload.split_at(ind+1);
                let first_package = PacketManifest {
                    ip: self.ip,
                    tcp: self.tcp,
                    tcp_payload: Payload(Cow::Borrowed(first_payload)),
                };
                let second_package = PacketManifest {
                    ip: self.ip,
                    tcp: TcpLayer {
                        seq: seq_no.into(),
                        ..self.tcp
                    },
                    tcp_payload: Payload(Cow::Borrowed(second_payload)),
                };
                (first_package, second_package)
            }
        }
    }
}

/// Payload is either borrowed by reference or cloned and lies somewhere on heap.
///
/// Provides only read-only interface to underlying data. It doesn't make possible to clone it
/// to prevent memory leaks.
#[derive(Debug)]
pub struct Payload<'p>(Cow<'p, [u8]>);

impl<'p> ops::Deref for Payload<'p> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

impl<'p> From<&'p [u8]> for Payload<'p> {
    fn from(payload: &'p [u8]) -> Self {
        Payload(payload.into())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct IpLayer {
    pub src: IpAddr,
    pub dst: IpAddr,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct TcpLayer {
    pub src: u16,
    pub dst: u16,
    pub ack: u32,
    pub seq: u32,
    pub flags: TcpFlags,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Flow {
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
}

impl<'p> From<&PacketManifest<'p>> for Flow {
    fn from(packet: &PacketManifest<'p>) -> Self {
        let src = (packet.ip.src, packet.tcp.src);
        let dst = (packet.ip.dst, packet.tcp.dst);
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
