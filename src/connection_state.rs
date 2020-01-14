use pnet::packet::Packet;
use pnet::packet::tcp::TcpFlags;

use crate::types::{Sequence, PacketManifest, SideIdentifier, Side};
use crate::utils::BitMask;
use std::net::IpAddr;

pub struct Connection {
    attack_detected: bool,
    side_id: SideIdentifier,
    packet_count: u64,
    skip_hijack_detection_count: u64,
    state: TcpState,
    client_next_seq: Sequence,
    server_next_seq: Sequence,
    hijack_next_ack: Sequence,
    first_syn_ack_seq: u32
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpState {
    Unknown,
    ConnectionRequest,
    ConnectionEstablished,
    DataTransfer,
    ConnectionClosing(TcpClosing),
    Invalid,
    Closed,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct TcpClosing {
    initiator: ClosingInitiator,
    initiator_state: TcpInitiatingClosingState,
    effector_state: TcpInitiatedClosingState,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ClosingInitiator {
    ThisSide,
    RemoteSide,
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
    pub fn receive_packet(&mut self, packet: PacketManifest) {
        self.packet_count += 1;

        match self.state {
            TcpState::Unknown
                => self.state_unknown(packet),
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

    fn state_unknown(&mut self, packet: PacketManifest) {
        self.side_id = SideIdentifier::new((IpAddr::V4(packet.ip.get_source()), packet.tcp.get_source()),
                                           (IpAddr::V4(packet.ip.get_destination()), packet.tcp.get_destination()));

        if packet.tcp.get_flags().bits(TcpFlags::SYN) && !packet.tcp.get_flags().bits(TcpFlags::ACK) {
            self.state = TcpState::ConnectionRequest;

            self.client_next_seq = Sequence::from(packet.tcp.get_sequence()) + packet.tcp.payload().len() as u32;
            self.hijack_next_ack = self.client_next_seq;
        } else {
            self.state = TcpState::DataTransfer;
            self.skip_hijack_detection_count = 0;
            self.client_next_seq = Sequence::from(packet.tcp.get_sequence()) + packet.tcp.payload().len() as u32;

            if packet.tcp.get_flags().bits(TcpFlags::FIN) || packet.tcp.get_flags().bits(TcpFlags::RST) {
                self.state = TcpState::Closed;
            }
        }
    }

    fn state_connection_request(&mut self, packet: PacketManifest) {
        if self.side_id.identify(&packet) == Side::Server {
            // handshake anomaly
            return
        }
        if !(packet.tcp.get_flags().bits(TcpFlags::SYN) && packet.tcp.get_flags().bits(TcpFlags::ACK)) {
            // handshake anomaly
            return
        }
        if self.client_next_seq - Sequence::from(packet.tcp.get_acknowledgement()) != 0 {
            // handshake anomaly
            return
        }
        self.state = TcpState::ConnectionEstablished;
        self.server_next_seq = Sequence::from(packet.tcp.get_sequence()) + (packet.tcp.payload().len() as u32 + 1);
        self.first_syn_ack_seq = packet.tcp.get_sequence();
    }

    fn state_connection_established(&mut self, packet: PacketManifest) {
        if !self.attack_detected {
            let hijack_detected = self.detect_hijack(&packet);
            if hijack_detected {
                self.attack_detected = true;
                return
            }
        }
        if self.side_id.identify(&packet) != Side::Client {
            // handshake anomaly
            return
        }
        if packet.tcp.get_flags().bits(TcpFlags::SYN) || !packet.tcp.get_flags().bits(TcpFlags::ACK) {
            // handshake anomaly
            return
        }
        if Sequence::from(packet.tcp.get_sequence()) != self.client_next_seq {
            // handshake anomaly
            return
        }
        if Sequence::from(packet.tcp.get_acknowledgement()) != self.server_next_seq {
            // handshake anomaly
            return
        }

        self.state = TcpState::DataTransfer;
    }

    fn state_data_transfer(&mut self, packet: PacketManifest) {}
    fn state_connection_closing(&mut self, packet: PacketManifest, state: TcpClosing) {}
    fn state_closed(&mut self, packet: PacketManifest) {}

    fn detect_hijack(&self, packet: &PacketManifest) -> bool {
        if self.side_id.identify(packet) != Side::Server {
            return false
        }
        if !packet.tcp.get_flags().bits(TcpFlags::ACK | TcpFlags::SYN) {
            return false
        }
        if Sequence::from(packet.tcp.get_sequence()) - self.hijack_next_ack != 0 {
            return false
        }
        if packet.tcp.get_sequence() == self.first_syn_ack_seq {
            return false
        }
        true // hijack detected
    }
}
