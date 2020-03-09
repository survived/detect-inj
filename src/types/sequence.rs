use std::{cmp, ops};

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug)]
pub struct Sequence(u32);

impl ops::Sub for Sequence {
    type Output = i64;
    fn sub(self, rhs: Sequence) -> i64 {
        i64::from(self.0) - i64::from(rhs.0)
    }
}

impl ops::Add<u32> for Sequence {
    type Output = Sequence;
    fn add(self, rhs: u32) -> Sequence {
        Sequence(self.0.wrapping_add(rhs))
    }
}

impl From<u32> for Sequence {
    fn from(seq: u32) -> Self {
        Sequence(seq)
    }
}

impl From<Sequence> for u32 {
    fn from(seq: Sequence) -> u32 {
        seq.0
    }
}

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
