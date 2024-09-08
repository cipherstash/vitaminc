use crate::{Equatable, Protect, Protected, ProtectNew};

/// Similar to `Default`, but doesn't rely on the standard library,
/// is only implemented for Paranoid types, and covers array sizes up to 1024.
pub trait Zeroed: Protect {
    fn zeroed() -> Self;
}

macro_rules! impl_zeroed_for_byte_array {
    ($N:expr) => {
        impl Zeroed for Protected<[u8; $N]> {
            fn zeroed() -> Self {
                Self::new([0; $N])
            }
        }
    };
}

impl<T> Zeroed for Equatable<T>
where
    T: Zeroed,
{
    fn zeroed() -> Self {
        Equatable(T::zeroed())
    }
}

/*impl<T> Zeroed for Exportable<T>
where
    T: Zeroed,
{
    fn zeroed() -> Self {
        Exportable(T::zeroed())
    }
}*/

impl_zeroed_for_byte_array!(1);
impl_zeroed_for_byte_array!(2);
impl_zeroed_for_byte_array!(3);
impl_zeroed_for_byte_array!(4);
impl_zeroed_for_byte_array!(5);
impl_zeroed_for_byte_array!(6);
impl_zeroed_for_byte_array!(7);
impl_zeroed_for_byte_array!(8);
impl_zeroed_for_byte_array!(9);
impl_zeroed_for_byte_array!(10);
impl_zeroed_for_byte_array!(11);
impl_zeroed_for_byte_array!(12);
impl_zeroed_for_byte_array!(13);
impl_zeroed_for_byte_array!(14);
impl_zeroed_for_byte_array!(15);
impl_zeroed_for_byte_array!(16);
impl_zeroed_for_byte_array!(17);
impl_zeroed_for_byte_array!(18);
impl_zeroed_for_byte_array!(19);
impl_zeroed_for_byte_array!(20);
impl_zeroed_for_byte_array!(21);
impl_zeroed_for_byte_array!(22);
impl_zeroed_for_byte_array!(23);
impl_zeroed_for_byte_array!(24);
impl_zeroed_for_byte_array!(25);
impl_zeroed_for_byte_array!(26);
impl_zeroed_for_byte_array!(27);
impl_zeroed_for_byte_array!(28);
impl_zeroed_for_byte_array!(29);
impl_zeroed_for_byte_array!(30);
impl_zeroed_for_byte_array!(31);
impl_zeroed_for_byte_array!(32);
impl_zeroed_for_byte_array!(48);
impl_zeroed_for_byte_array!(64);
impl_zeroed_for_byte_array!(128);
impl_zeroed_for_byte_array!(256);
impl_zeroed_for_byte_array!(512);
impl_zeroed_for_byte_array!(1024);
