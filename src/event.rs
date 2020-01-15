use time::PrimitiveDateTime;

use crate::types::packet::Flow;

pub trait AttackReporter {
    fn is_attack_detected(&self) -> bool;
    fn report_attack(&mut self, report: AttackReport);
}

pub enum AttackReport {
    HandshakeHijack {
        time: PrimitiveDateTime,
        packet_count: u64,
        flow: Flow,
        hijack_seq: u32,
        hijack_ack: u32,
    }
}
