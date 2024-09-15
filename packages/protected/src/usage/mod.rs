use serde::{Serialize, Serializer};

use crate::{exportable::SafeSerialize, private::ControlledPrivate, Controlled, Protected};
use std::marker::PhantomData;

// TODO: Docs, explain compile time
pub struct Usage<T, Scope = DefaultScope>(pub(crate) T, pub(crate) PhantomData<Scope>);

impl<T, S> Usage<T, S> {
    pub fn new(x: <Usage<T, S> as ControlledPrivate>::Inner) -> Self
    where
        Self: Controlled,
        S: Scope,
    {
        Self::init_from_inner(x)
    }
}

impl<T: ControlledPrivate, Scope> ControlledPrivate for Usage<T, Scope> {
    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x), PhantomData)
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
    }
}

impl<T, Scope> Controlled for Usage<T, Scope>
where
    T: Controlled,
{
    fn risky_unwrap(self) -> Self::Inner {
        self.0.risky_unwrap()
    }
}

/// Marker trait for a type that defines a usage scope
pub trait Scope {}

/// Marker trait for types that are acceptable in a certain scope.
pub trait Acceptable<S>
where
    S: Scope,
{
}

impl<T, S> Acceptable<S> for Usage<T, S> where S: Scope {}

// TODO: Move this to all of the other modules
pub struct DefaultScope;
impl Scope for DefaultScope {}
impl<T> Acceptable<DefaultScope> for Protected<T> {}

/// Serialize implementation for Usage if it is controlled and the inner type is safe serializable.
///
/// For example, this allows us to serialize a `Usage<Exportable<Protected<[u8; 32]>>>` type.
impl<T, A> Serialize for Usage<T, A>
where
    T: ControlledPrivate,
    T::Inner: SafeSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner().safe_serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MyScope;
    impl Scope for MyScope {}

    // TODO: Create some compilation tests
    fn example1<T: Acceptable<DefaultScope>>(_: T) -> bool {
        true
    }
    fn example2<T: Acceptable<MyScope>>(_: T) -> bool {
        true
    }

    #[test]
    fn test_usage_for_default_scope() {
        let x: Usage<Protected<[u8; 32]>, DefaultScope> = Usage::new([0u8; 32]);

        assert!(example1(x));
    }

    #[test]
    fn test_usage_for_specific_scope() {
        let x: Usage<Protected<[u8; 32]>, MyScope> = Usage::new([0; 32]);

        assert!(example2(x));
    }
}
