use time::PrimitiveDateTime;

use crate::types::packet::Flow;

pub trait AttackReporter {
    fn is_attack_detected(&self) -> bool;
    fn report_attack(&mut self, report: AttackReport);
}

#[derive(Debug)]
pub enum AttackReport {
    HandshakeHijack {
        time: PrimitiveDateTime,
        packet_count: u64,
        flow: Flow,
        hijack_seq: u32,
        hijack_ack: u32,
    }
}

#[derive(Default)]
pub struct ConsoleReporter {
    attack_reported: bool
}

impl AttackReporter for ConsoleReporter {
    fn is_attack_detected(&self) -> bool {
        self.attack_reported
    }

    fn report_attack(&mut self, report: AttackReport) {
        self.attack_reported = true;
        eprintln!("Reported attack: {:?}", report);
    }
}
