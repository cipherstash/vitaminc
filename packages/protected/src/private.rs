use crate::{Protect, ProtectInit};

/// ParanoidPrivate is a private trait that is used to hide the inner value of a Paranoid type.
/// It is pub but within a private module.
pub trait ProtectSealed {
    //type Inner: ProtectAdapter;
}

/*impl<const N: usize> ProtectSealed for [u8; N] {
    type Inner = [u8; N];
}*/

impl<T> ProtectSealed for super::Protected<T> {}
impl<T> ProtectSealed for super::Equatable<T> {}
impl<T> ProtectSealed for super::Exportable<T> {}
impl<T, S> ProtectSealed for super::Usage<T, S> {}
impl<T> ProtectSealed for T
where
    T: ProtectInit,
    <T as ProtectInit>::Inner: Protect,
{
}
