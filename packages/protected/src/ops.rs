use std::ops::BitXor;
use zeroize::Zeroize;

use crate::{Controlled, Protected};

impl<T> BitXor for Protected<T>
where
    T: BitXor + Zeroize,
    <T as BitXor>::Output: Zeroize,
{
    type Output = Protected<T::Output>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.zip(rhs, |x, y| x ^ y)
    }
}
