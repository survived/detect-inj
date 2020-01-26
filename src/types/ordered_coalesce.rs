use std::cmp;
use std::collections::BTreeMap;

use crate::types::{Sequence, PacketManifest, Payload};

/// Range of sequence number within package fits.
///
/// We assume that two SequenceRange are equal if them intersect. This helps us to
/// detect overlaps.
#[derive(Copy, Clone, Debug)]
pub struct SequenceRange {
    pub from: Sequence,
    pub to: Sequence,
}

impl cmp::PartialEq for SequenceRange {
    fn eq(&self, other: &SequenceRange) -> bool {
        other.from <= self.to && self.from <= other.to
    }
}

impl cmp::PartialOrd for SequenceRange {
    fn partial_cmp(&self, other: &SequenceRange) -> Option<cmp::Ordering> {
        Some(<Self as cmp::Ord>::cmp(self, other))
    }
}

impl cmp::Eq for SequenceRange {}

impl cmp::Ord for SequenceRange {
    fn cmp(&self, other: &SequenceRange) -> cmp::Ordering {
        if self.to < other.from {
            cmp::Ordering::Less
        } else if self.from > other.to {
            cmp::Ordering::Greater
        } else {
            cmp::Ordering::Equal
        }
    }
}

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
        let mut range = SequenceRange {
            from: Sequence::from(packet.tcp.seq),
            to: Sequence::from(packet.tcp.seq) + packet.tcp_payload.len() as u32,
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
        for (&overlapping_range, overlapping_package) in self.collection.range(range..=range) {
            // iterating here over all packages which
            // ranges intersect with being inserted
            // package range
            debug_assert_eq!(overlapping_range, range, "ranges must overlap");

            if self.construct_overlap_blocks_enabled() {
                let overlap = SequenceRange {
                    from: cmp::max(overlapping_range.from, range.from),
                    to:   cmp::min(overlapping_range.to, range.to),
                };
                let payload_range =  Into::<u32>::into(overlap.from) as usize..=Into::<u32>::into(overlap.to) as usize;
                if payload[payload_range.clone()] != overlapping_package.tcp_payload[payload_range.clone()] {
                    overlaping_blocks.push(OverlapBlock {
                        winner: overlapping_package.tcp_payload[payload_range.clone()].to_vec().into_boxed_slice(),
                        loser:  payload[payload_range.clone()].to_vec().into_boxed_slice(),
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
    /// corresponding to every range.
    fn split_packet_into_sub_packets(packet: PacketManifest<'static>, ranges: &[SequenceRange]) -> Vec<(SequenceRange, PacketManifest<'static>)> {
        let mut sub_packages = vec![];
        let mut packet = Some(packet);
        for &range in ranges {
            let (_, sub_packet) = packet.take().expect("it might be None only within iteration")
                .split_at(range.from);
            let (corresponding_packet, rest_of_packet) = sub_packet.split_at(range.to);
            sub_packages.push((range, corresponding_packet));
            packet = Some(rest_of_packet)
        }
        sub_packages
    }
}

pub struct OverlapBlock {
    pub winner: Box<[u8]>,
    pub loser:  Box<[u8]>,
    pub range:  SequenceRange,
}
