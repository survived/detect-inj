use std::net::IpAddr;

use time::PrimitiveDateTime;
use pnet::packet::Packet;
use pnet::packet::tcp::TcpFlags;

use crate::types::{Sequence, PacketManifest, SideIdentifier, Side, Flow};
use crate::utils::BitMask;
use crate::event::{AttackReporter, AttackReport};

pub struct ConnectionOptions {
    pub attack_reporter: Box<dyn AttackReporter>,
    pub skip_hijack_detection_count: u64
}

pub struct Connection {
    attack_reporter: Box<dyn AttackReporter>,
    side_id: SideIdentifier,
    packet_count: u64,
    skip_hijack_detection_count: u64,
    hijack_next_ack: Sequence,
    state: TcpState,
    client_next_seq: Sequence,
    server_next_seq: Option<Sequence>,
    first_syn_ack_seq: Option<u32>,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpState {
    ConnectionRequest,
    ConnectionEstablished,
    DataTransfer,
    ConnectionClosing(TcpClosing),
    Invalid,
    Closed,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct TcpClosing {
    initiator: Side,
    initiator_state: TcpInitiatingClosingState,
    effector_state: TcpInitiatedClosingState,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpInitiatingClosingState {
    FinWait1,
    FinWait2,
    TimeWait,
    Closing,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpInitiatedClosingState {
    CloseWait,
    LastAck,
}

impl Connection {
    pub fn from_packet(packet: PacketManifest, options: ConnectionOptions) -> Self {
        let is_initial_packet = packet.tcp.flags.syn && !packet.tcp.flags.ack;
        let is_closing_packet = !is_initial_packet && (packet.tcp.flags.fin || packet.tcp.flags.rst);
        let client_next_seq = Sequence::from(packet.tcp.seq) + 1 + packet.tcp_payload.len() as u32;

        Self {
            attack_reporter: options.attack_reporter,
            state: if is_initial_packet { TcpState::ConnectionRequest }
                   else if is_closing_packet { TcpState::Closed }
                   else { TcpState::DataTransfer },
            client_next_seq,
            server_next_seq: None,
            skip_hijack_detection_count: if is_initial_packet { options.skip_hijack_detection_count } else { 0 },
            hijack_next_ack: if is_initial_packet { client_next_seq } else { Sequence::from(0) },
            packet_count: 1,
            first_syn_ack_seq: None,
            side_id: SideIdentifier::from_client_flow(Flow::from(&packet)),
        }
    }

    pub fn receive_packet(&mut self, packet: PacketManifest) {
        self.packet_count += 1;

        match self.state {
            TcpState::ConnectionRequest
                => self.state_connection_request(packet),
            TcpState::ConnectionEstablished
                => self.state_connection_established(packet),
            TcpState::DataTransfer
                => self.state_data_transfer(packet),
            TcpState::ConnectionClosing(sub_state)
                => self.state_connection_closing(packet, sub_state),
            TcpState::Closed
                => self.state_closed(packet),
            TcpState::Invalid => {
                // TODO: what do we do here?
            }
        }
    }

    fn state_connection_request(&mut self, packet: PacketManifest) {
        if self.side_id.identify(&packet) != Side::Server {
            // handshake anomaly
            return
        }
        if !(packet.tcp.flags.syn && packet.tcp.flags.ack) {
            // handshake anomaly
            return
        }
        if self.client_next_seq - Sequence::from(packet.tcp.ack) != 0 {
            // handshake anomaly
            return
        }
        self.state = TcpState::ConnectionEstablished;
        self.server_next_seq = Some(Sequence::from(packet.tcp.seq) + (packet.tcp_payload.len() as u32 + 1));
        self.first_syn_ack_seq = Some(packet.tcp.seq);
    }

    fn state_connection_established(&mut self, packet: PacketManifest) {
        if !self.attack_reporter.is_attack_detected() {
            if let Some(report) = self.detect_hijack(&packet) {
                self.attack_reporter.report_attack(report);
            }
        }
        if self.side_id.identify(&packet) != Side::Client {
            // handshake anomaly
            return
        }
        if packet.tcp.flags.syn || !packet.tcp.flags.ack {
            // handshake anomaly
            return
        }
        if Sequence::from(packet.tcp.seq) != self.client_next_seq {
            // handshake anomaly
            return
        }
        if Some(Sequence::from(packet.tcp.ack)) != self.server_next_seq {
            // handshake anomaly
            return
        }

        self.state = TcpState::DataTransfer;
    }

    fn state_data_transfer(&mut self, packet: PacketManifest) {
        if self.server_next_seq.is_none() && self.side_id.identify(&packet) == Side::Server {
            self.server_next_seq = Some(Sequence::from(packet.tcp.seq));
        }

        if self.packet_count < self.skip_hijack_detection_count {
            if let Some(report) = self.detect_hijack(&packet) {
                self.attack_reporter.report_attack(report);
            }
        }
    }

    fn state_connection_closing(&mut self, packet: PacketManifest, state: TcpClosing) {}
    fn state_closed(&mut self, packet: PacketManifest) {}

    fn detect_hijack(&self, packet: &PacketManifest) -> Option<AttackReport> {
        if self.side_id.identify(packet) != Side::Server {
            return None
        }
        if !packet.tcp.flags.ack || !packet.tcp.flags.syn {
            return None
        }
        if Sequence::from(packet.tcp.ack) != self.hijack_next_ack {
            return None
        }
        if Some(packet.tcp.seq) == self.first_syn_ack_seq {
            return None
        }
        Some(AttackReport::HandshakeHijack {
            time: PrimitiveDateTime::now(),
            packet_count: self.packet_count,
            flow: Flow::from(packet),
            hijack_seq: packet.tcp.seq,
            hijack_ack: packet.tcp.ack,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::test_utils::DummyAttackReporter;
    use crate::types::{IpLayer, TcpLayer, TcpFlags};

    use std::rc::Rc;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    #[test]
    fn detect_tcp_hijack() {
        let shared_reports: Rc<RefCell<Vec<_>>> = Default::default();
        let connection_options = ConnectionOptions {
            skip_hijack_detection_count: 12,
            attack_reporter: Box::new(DummyAttackReporter::new(shared_reports.clone())),
        };

        let client_ip = IpLayer {
            src: Ipv4Addr::new(1, 2, 3, 4).into(),
            dst: Ipv4Addr::new(2, 3, 4, 5).into(),
        };
        let server_ip = IpLayer {
            src: Ipv4Addr::new(2, 3, 4, 5).into(),
            dst: Ipv4Addr::new(1, 2, 3, 4).into(),
        };

        // initial packet

        let packet = PacketManifest {
            ip: client_ip,
            tcp: TcpLayer {
                src: 1,
                dst: 2,
                seq: 3,
                flags: TcpFlags {
                    syn: true,
                    ack: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            tcp_payload: &[],
        };
        let mut connection = Connection::from_packet(packet, connection_options);
        assert_eq!(connection.state, TcpState::ConnectionRequest, "invalid state transaction");

        // next packet
        connection.receive_packet(PacketManifest {
            ip: server_ip,
            tcp: TcpLayer {
                src: 2,
                dst: 1,
                seq: 9,
                ack: 4,
                flags: TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
            },
            tcp_payload: &[],
        });
        assert_eq!(connection.state, TcpState::ConnectionEstablished, "invalid state transaction");

        // test hijack
        connection.receive_packet(PacketManifest {
            ip: server_ip,
            tcp: TcpLayer {
                src: 2,
                dst: 1,
                seq: 6699,
                ack: 4,
                flags: TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
            },
          tcp_payload: &[],
        });

        let reports_count = shared_reports.borrow().len();
        assert_eq!(reports_count, 1, "hijack detection fail");

        // Going to data transfer state
        connection.receive_packet(PacketManifest {
            ip: client_ip,
            tcp: TcpLayer {
                src: 1,
                dst: 2,
                seq: 4,
                ack: 10,
                flags: TcpFlags {
                    syn: false,
                    ack: true,
                    ..Default::default()
                },
            },
            tcp_payload: &[],
        });
        assert_eq!(connection.state, TcpState::DataTransfer, "invalid state transition");

        // test hijack in transfer state
        connection.receive_packet(PacketManifest {
            ip: server_ip,
            tcp: TcpLayer {
                src: 2,
                dst: 1,
                seq: 7711,
                ack: 4,
                flags: TcpFlags {
                    syn: true,
                    ack: true,
                    ..Default::default()
                },
            },
            tcp_payload: &[],
        });
        let reports_count = shared_reports.borrow().len();
        assert_eq!(reports_count, 2, "hijack detection fail");
    }
}
