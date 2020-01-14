pub trait BitMask {
    fn bits(self, mask: Self) -> bool;
}

// Implements BitMask for u8, u16, u32, u64
impl<N> BitMask for N
    where u64: From<Self> + From<N>
{
    fn bits(self, mask: N) -> bool {
        let (me, mask) = (u64::from(self), u64::from(mask));
        (me & mask) == mask
    }
}
