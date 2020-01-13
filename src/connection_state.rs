use crate::types::{Sequence, PacketManifest};

pub struct Connection {
    attack_detected: bool,
    packet_count: u64,
    skip_hijack_detection_count: u64,
    state: TcpState,
    client_next_sequence: Sequence,
    server_next_sequence: Sequence,
    hijack_next_ack: Sequence,
    first_syn_ack_seq: u32
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpState {
    Unknown,
    ConnectionRequest,
    ConnectionEstablished,
    DataTransfer,
    ConnectionClosing(TcpClosing),
    Invalid,
    Closed,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub struct TcpClosing {
    initiator: ClosingInitiator,
    initiator_state: TcpInitiatingClosingState,
    effector_state: TcpInitiatedClosingState,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub enum ClosingInitiator {
    ThisSide,
    RemoteSide,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub enum TcpInitiatingClosingState {
    FinWait1,
    FinWait2,
    TimeWait,
    Closing,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
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

    fn state_unknown(&mut self, packet: PacketManifest) {}
    fn state_connection_request(&mut self, packet: PacketManifest) {}
    fn state_connection_established(&mut self, packet: PacketManifest) {}
    fn state_data_transfer(&mut self, packet: PacketManifest) {}
    fn state_connection_closing(&mut self, packet: PacketManifest, state: TcpClosing) {}
    fn state_closed(&mut self, packet: PacketManifest) {}
}
