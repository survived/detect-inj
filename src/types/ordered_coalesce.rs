use std::cmp;
use std::collections::BTreeMap;

use crate::types::{Sequence, SequenceRange, PacketManifest, Payload};

/// Tracks out-of-order packages to coalesce them as soon as it will be possible.
///
/// Every insertion into `OrderedCoalesce` triggers overlap checking to detect injections.
/// It also calculates summary weight of all package payloads (length in bytes).
pub struct OrderedCoalesce {
    total_size: u64,
    collection: BTreeMap<SequenceRange, PacketManifest<'static>>,
}

impl OrderedCoalesce {
    pub fn new() -> Self {
        Self {
            total_size: 0,
            collection: BTreeMap::new(),
        }
    }

    /// Puts given package in OrderedCoalesce, gives back `OverlapBlock`s if there're any and
    /// their constructing is enabled.
    pub fn insert(&mut self, packet: PacketManifest<'static>) -> Option<Vec<OverlapBlock>> {
        if packet.tcp_payload.is_empty() {
            // Ignore empty packets
            return Some(vec![]).filter(|_| self.construct_overlap_blocks_enabled())
        }

        let range = SequenceRange {
            from: Sequence::from(packet.tcp.seq),
            to: Sequence::from(packet.tcp.seq) + (packet.tcp_payload.len() - 1) as u32,
        };

        let (not_overlapping, overlap_blocks) = self.overlap_check(range, &packet.tcp_payload);
        let not_overlapping_packets = Self::split_packet_into_sub_packets(packet, &not_overlapping);

        for (range, packet) in not_overlapping_packets {
            self.collection.insert(range, packet);
            self.total_size += (range.to - range.from) as u64;
        }

        overlap_blocks
    }

    /// Test given segment and sequence range it fits in against overlapping with existing
    /// segments.
    ///
    /// # Return
    /// Returns that pieces of sequence range which doesn't intersect any existing range (note that
    /// original range may be splitten in several pieces). If enabled, attaches `OverlapBlock` which
    /// may be used to compare overlapping data
    fn overlap_check(&self, range: SequenceRange, payload: &Payload) -> (Vec<SequenceRange>, Option<Vec<OverlapBlock>>) {
        let mut not_overlapping = vec![range];
        let mut overlaping_blocks = vec![];
        for (&overlapping_range, overlapping_package) in self.collection.range(range..) {
            // iterating here over all packages which
            // ranges intersect with being inserted
            // package range
            if overlapping_range != range {
                break;
            }

            if self.construct_overlap_blocks_enabled() {
                let overlap = SequenceRange {
                    from: cmp::max(overlapping_range.from, range.from),
                    to:   cmp::min(overlapping_range.to, range.to),
                };
                let looser = payload.sub_payload(overlap, range.from);
                let winner = overlapping_package.tcp_payload.sub_payload(overlap, Sequence::from(overlapping_package.tcp.seq));
                // let winner = overlapping_package.tcp_payload.sub_payload(overlap, overlapping_range.from);
                if winner != looser {
                    overlaping_blocks.push(OverlapBlock {
                        winner: winner.to_vec().into_boxed_slice(),
                        loser:  looser.to_vec().into_boxed_slice(),
                        range:  overlap,
                    });
                }
            }

            let range = not_overlapping.pop().expect("guaranteed to have at least one element");
            if range.from <= overlapping_range.from {
                not_overlapping.push(SequenceRange {
                    from: range.from,
                    to: overlapping_range.from,
                })
            }
            if overlapping_range.to <= range.to {
                not_overlapping.push(SequenceRange {
                    from: overlapping_range.to,
                    to: range.to,
                })
            } else {
                break
            }
        }
        (not_overlapping, if self.construct_overlap_blocks_enabled() { Some(overlaping_blocks) } else { None })
    }

    // TODO: make it settable
    fn construct_overlap_blocks_enabled(&self) -> bool {
        true
    }

    /// Takes a packet and ordered nonoverlapping ranges within it, produces subpackets
    /// corresponding to every range. Ranges are inclusive.
    fn split_packet_into_sub_packets(packet: PacketManifest<'static>, ranges: &[SequenceRange]) -> Vec<(SequenceRange, PacketManifest<'static>)> {
        ranges.into_iter().scan(packet, |packet, &range| {
            let mut sub_packet = packet.split_off(range.from);
            let everything_else = sub_packet.split_off(range.to + 1);
            *packet = everything_else;
            Some((range, sub_packet))
        }).collect()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct OverlapBlock {
    pub winner: Box<[u8]>,
    pub loser:  Box<[u8]>,
    pub range:  SequenceRange,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, IpAddr};

    use super::*;
    use crate::types::*;
    use crate::types::packet::tests::tcp_packet;
    use std::sync::atomic::Ordering::SeqCst;

    #[test]
    fn not_detect_overlapping_block_if_there_is_none() {
        let mut detector = OrderedCoalesce::new();
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(0, &[1,2,3])));
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(6, &[7,8])));
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(3, &[4,5,6])));
    }

    #[test]
    fn detect_coalesce_within_single_packet() {
        let mut detector = OrderedCoalesce::new();
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(0, &[1,2,3,4,5,6])));
        let overlaps = detector.insert(tcp_packet(1, &[10,11,12]));
        let overlap_expected = OverlapBlock {
            winner: vec![2,3,4].into_boxed_slice(),
            loser:  vec![10,11,12].into_boxed_slice(),
            range: SequenceRange {
                from: Sequence::from(1),
                to:   Sequence::from(3),
            }
        };
        assert_eq!(overlaps, Some(vec![overlap_expected]));
    }

    #[test]
    fn not_detect_overlap_if_competitors_are_equal() {
        let mut detector = OrderedCoalesce::new();
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(0, &[1,2,3])));
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(6, &[7,8])));
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(3, &[4,5,6])));

        assert_eq!(Some(vec![]), detector.insert(tcp_packet(2, &[3,4,5,6,7])));
    }

    #[test]
    fn detect_overlap_within_several_packets() {
        let mut detector = OrderedCoalesce::new();
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(0, &[1,2,3])));
        assert_eq!(Some(vec![]), detector.insert(tcp_packet(3, &[4,5,6])));

        let overlap = detector.insert(tcp_packet(2, &[10,11]));
        let expected_overlap1 = OverlapBlock {
            winner: vec![3].into_boxed_slice(),
            loser: vec![10].into_boxed_slice(),
            range: SequenceRange {
                from: Sequence::from(2),
                to: Sequence::from(2),
            },
        };
        let expected_overlap2 = OverlapBlock {
            winner: vec![4].into_boxed_slice(),
            loser: vec![11].into_boxed_slice(),
            range: SequenceRange {
                from: Sequence::from(3),
                to: Sequence::from(3),
            },
        };
        assert_eq!(overlap, Some(vec![expected_overlap1, expected_overlap2]))
    }

    #[test]
    fn split_packet_into_sub_packets() {
        let payload = (0..10).collect::<Vec<_>>();
        let original_packet = tcp_packet(0, &payload);
        let ranges = &[
            SequenceRange {
                from: Sequence::from(0),
                to: Sequence::from(0),
            },
            SequenceRange {
                from: Sequence::from(3),
                to: Sequence::from(6),
            },
            SequenceRange {
                from: Sequence::from(8),
                to: Sequence::from(9),
            },
        ];

        let actual = OrderedCoalesce::split_packet_into_sub_packets(original_packet, ranges);
        let expected = vec![
            (ranges[0], tcp_packet(0, &payload[0..=0])),
            (ranges[1], tcp_packet(3, &payload[3..=6])),
            (ranges[2], tcp_packet(8, &payload[8..=9])),
        ];

        assert_eq!(actual, expected);
    }
}
