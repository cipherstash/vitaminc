use serde::{Serialize, Serializer};

use crate::{exportable::SafeSerialize, private::ControlledPrivate, Controlled, Protected};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO: Docs, explain compile time
pub struct Usage<T, Scope = DefaultScope>(pub(crate) T, pub(crate) PhantomData<Scope>);

impl<T, S> Usage<T, S> {
    pub fn new(x: <Usage<T, S> as Controlled>::Inner) -> Self
    where
        Self: Controlled,
        S: Scope,
    {
        Self::init_from_inner(x)
    }
}

// `Usage` is a compile-time scope wrapper; this `Zeroize` impl exists only to
// satisfy the `Controlled: Zeroize` supertrait and delegates to the inner type
// (`PhantomData` is a ZST with nothing to wipe).
//
// `Usage` intentionally has no `Drop` (and so no `ZeroizeOnDrop` *derive*) of
// its own: the wipe is whatever drop glue the field `T` brings. Every path that
// can put a secret into a `Usage` goes through `Controlled` (`Usage::new`,
// `init_from_inner`, `inner_mut`), and `Controlled for Usage` requires
// `T: Controlled`, so a `Usage` holding a secret always has a
// `Protected`/`Equatable`/`Exportable` field whose `ZeroizeOnDrop` wipes the
// bytes when `Usage` drops. The one constructor without that bound,
// `Zeroed for Usage`, can build e.g. `Usage<[u8; 32], S>`, but such a value is
// inert: it holds only zeros and exposes no way to write a secret into it.
// Giving `Usage` its own `Drop` would require a viral `T: Zeroize` bound on the
// struct (E0367: a conditional `Drop` must match the struct bounds), which would
// cascade through every `Usage<T, S>` use for no behavioural gain.
impl<T: Zeroize, Scope> Zeroize for Usage<T, Scope> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// `ZeroizeOnDrop` is a method-less marker, so unlike a `Drop` impl it needs no
// struct-level bound (the same pattern as `ProtectedDigest`). It is correct
// exactly when the field is `ZeroizeOnDrop`: `PhantomData` holds nothing, so
// the field's drop glue is the whole of `Usage`'s drop. Without this impl every
// `T: ZeroizeOnDrop` bound downstream would reject `Usage<..>` and force
// callers to strip the scope wrapper first.
impl<T: ZeroizeOnDrop, Scope> ZeroizeOnDrop for Usage<T, Scope> {}

impl<T: ControlledPrivate, Scope> ControlledPrivate for Usage<T, Scope> {}

impl<T, Scope> Controlled for Usage<T, Scope>
where
    T: Controlled,
{
    fn risky_unwrap(self) -> Self::Inner {
        self.0.risky_unwrap()
    }

    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x), PhantomData)
    }

    fn risky_ref(&self) -> &Self::Inner {
        self.0.risky_ref()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
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
impl<T: Zeroize> Acceptable<DefaultScope> for Protected<T> {}

/// Serialize implementation for Usage if it is controlled and the inner type is safe serializable.
///
/// For example, this allows us to serialize a `Usage<Exportable<Protected<[u8; 32]>>>` type.
impl<T, A> Serialize for Usage<T, A>
where
    T: Controlled,
    T::Inner: SafeSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.risky_ref().safe_serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{assert_zeroize_on_drop, Tracked};
    use std::sync::atomic::AtomicBool;

    struct MyScope;
    impl Scope for MyScope {}

    /// `Usage` has no `Drop` of its own (see the note on the `Zeroize` impl
    /// above): the wipe is the inner wrapper's drop glue, reached through
    /// `Usage`'s field. This observes the wipe directly, so it fails if
    /// `Usage` ever stops letting the field's `Drop` run (e.g. by wrapping it
    /// in `ManuallyDrop`), regardless of what other destructors exist.
    #[test]
    fn drop_wipes_through_inner_wrapper() {
        let zeroized = AtomicBool::new(false);
        let tracked = Tracked(&zeroized);
        {
            let _u = Usage::<Protected<Tracked<'_>>, DefaultScope>::new(tracked);
            assert!(!tracked.was_zeroized());
        }
        assert!(
            tracked.was_zeroized(),
            "dropping Usage must run the inner wrapper's zeroizing Drop"
        );
    }

    /// The `ZeroizeOnDrop` marker on `Usage` follows the inner wrapper, so
    /// `Usage<..>` satisfies the same `T: ZeroizeOnDrop` bounds its payload
    /// does. Nested inside `Option` too, as callers commonly hold it.
    #[test]
    fn usage_is_zeroize_on_drop_when_inner_is() {
        assert_zeroize_on_drop::<Usage<Protected<[u8; 32]>, DefaultScope>>();
        assert_zeroize_on_drop::<Option<Usage<Protected<[u8; 32]>, MyScope>>>();
    }

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
