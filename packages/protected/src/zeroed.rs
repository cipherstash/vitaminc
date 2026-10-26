use std::marker::PhantomData;

use crate::{Equatable, Exportable, Protected, Usage};
use zeroize::Zeroize;

/// Construct a zero or empty value for supported primitives, arrays, and wrappers.
/// Unlike `Default`, the intended initial state is explicitly zero/empty.
pub trait Zeroed {
    /// Construct a value in its zero or empty state. This does not by itself
    /// guarantee wiping on drop; use a wrapper such as [`Protected`] for that.
    fn zeroed() -> Self;
}

macro_rules! impl_zeroed_for_array {
    ($t:ty, $($N:expr),+) => {
        $(
            impl Zeroed for [$t; $N] {
                fn zeroed() -> Self {
                    [0; $N]
                }
            }
        )+
    };
}

macro_rules! impl_zeroed_for_literal {
    ($($t:ty),+) => {
        $(
            impl Zeroed for $t {
                fn zeroed() -> Self {
                    0
                }
            }
        )+
    };
}

impl<T> Zeroed for Protected<T>
where
    T: Zeroed + Zeroize,
{
    fn zeroed() -> Self {
        Protected(T::zeroed())
    }
}

impl<T> Zeroed for Equatable<T>
where
    T: Zeroed + Zeroize,
{
    fn zeroed() -> Self {
        Equatable(T::zeroed())
    }
}

impl<T> Zeroed for Exportable<T>
where
    T: Zeroed + Zeroize,
{
    fn zeroed() -> Self {
        Exportable(T::zeroed())
    }
}

impl<T, S> Zeroed for Usage<T, S>
where
    T: Zeroed,
{
    fn zeroed() -> Self {
        Usage(T::zeroed(), PhantomData)
    }
}

impl_zeroed_for_array!(
    u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 48, 64, 128, 256, 512, 1024
);
impl_zeroed_for_array!(
    u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 48, 64, 128, 256, 512
);
impl_zeroed_for_array!(
    u32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 48, 64, 128, 256
);
impl_zeroed_for_literal!(u8, u16, u32, u64, u128);
