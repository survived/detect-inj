use std::ops;

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub struct Sequence(u32);

impl ops::Sub for Sequence {
    type Output = i64;
    fn sub(self, rhs: Sequence) -> i64 {
        self.0.into() - rhs.0.into()
    }
}

impl ops::Add<u32> for Sequence {
    type Output = Sequence;
    fn add(self, rhs: u32) -> Sequence {
        Sequence(self.0.wrapping_add(rhs))
    }
}
