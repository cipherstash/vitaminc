use std::ops::BitXor;
use zeroize::Zeroize;

use crate::{Protected, ProtectNew};

// TODO: These ops could be generalised for all Paranoid types by using the zip trait method on Paranoid.
// Alternatively, we could create another wrapper type so that Ops are explicitly opted into.

impl<T> BitXor for Protected<T>
where
    T: BitXor + Zeroize,
    <T as BitXor>::Output: Zeroize,
{
    type Output = Protected<T::Output>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Protected::new(self.0 ^ rhs.0)
    }
}
