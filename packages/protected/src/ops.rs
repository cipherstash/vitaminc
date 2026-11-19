use std::ops::BitXor;
use zeroize::Zeroize;

use crate::{Controlled, Protected};

impl<T, O> BitXor for Protected<T>
where
    T: Zeroize,
    for<'a> &'a T: BitXor<&'a T, Output = O>,
    O: Zeroize,
{
    type Output = Protected<O>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.zip(rhs, |x, y| x ^ y)
    }
}
