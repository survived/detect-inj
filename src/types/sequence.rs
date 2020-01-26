use std::ops;

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

impl Into<u32> for Sequence {
    fn into(self) -> u32 {
        self.0
    }
}
