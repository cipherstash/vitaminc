use crate::{Equatable, Exportable, Protected};

/// Similar to `Default`, but doesn't rely on the standard library,
/// is only implemented for Paranoid types, and covers array sizes up to 1024.
pub trait Zeroed {
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
    T: Zeroed,
{
    fn zeroed() -> Self {
        Protected(T::zeroed())
    }
}

impl<T> Zeroed for Equatable<T>
where
    T: Zeroed,
{
    fn zeroed() -> Self {
        Equatable(T::zeroed())
    }
}

impl<T> Zeroed for Exportable<T>
where
    T: Zeroed,
{
    fn zeroed() -> Self {
        Exportable(T::zeroed())
    }
}

impl_zeroed_for_array!(u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 48, 64, 128, 256, 512, 1024);
impl_zeroed_for_array!(u16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 48, 64, 128, 256, 512);
impl_zeroed_for_literal!(u8, u16, u32, u64, u128);