use crate::{Controlled, ControlledInit};

/// ParanoidPrivate is a private trait that is used to hide the inner value of a Paranoid type.
/// It is pub but within a private module.
pub trait ProtectSealed {}

impl<T> ProtectSealed for super::Protected<T> {}
impl<T> ProtectSealed for super::Equatable<T> {}
impl<T> ProtectSealed for super::Exportable<T> {}
impl<T, S> ProtectSealed for super::Usage<T, S> {}
impl<T> ProtectSealed for T
where
    T: ControlledInit,
    <T as ControlledInit>::Inner: Controlled,
{
}
