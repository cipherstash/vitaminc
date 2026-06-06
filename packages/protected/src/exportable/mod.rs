mod safe_deserialize;
mod safe_serialize;
use crate::{equatable::ConstantTimeEq, private::ControlledPrivate, Controlled};
use serde::{
    de::{Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use safe_deserialize::SafeDeserialize;
pub use safe_serialize::SafeSerialize;

/// Exportable is a wrapper type that allows for controlled types to be serialized and deserialized.
/// Serialization has a bias towards efficient byte representation and uses `serde_bytes` for byte arrays.
///
/// In the future, this will only work for Serializers that are marked with a `SafeSerializer` trait.
/// The goal here is to avoid leaking secrets through serialization (due to timing and other side channel attacks).
///
/// Exportable works just like any other controlled type, but it can be serialized and deserialized.
///
/// # Example
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Controlled, Exportable, Protected};
/// use serde::{Serialize, Deserialize};
///
/// pub type Secret = Exportable<Protected<[u8; 32]>>;
/// let secret = Secret::new([0u8; 32]);
/// let serialized = serde_json::to_string(&secret).unwrap();
/// let deserialized: Secret = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(secret.risky_unwrap(), deserialized.risky_unwrap());
/// ```
///
/// # Nesting other controlled types
///
/// You can nest an [crate::Equatable] within an [Exportable] so that the type also implements `ConstantTimeEq`.
/// Note that the order of the nesting does not matter.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Controlled, Exportable, Equatable, Protected};
/// use serde::{Serialize, Deserialize};
///
/// // Nesting order does not matter
/// pub type SecretA = Exportable<Equatable<Protected<[u8; 32]>>>;
/// pub type SecretB = Equatable<Exportable<Protected<[u8; 32]>>>;
/// let secret_a = SecretA::new([0u8; 32]);
/// let secret_b = SecretB::new([0u8; 32]);
///
/// // Timing safe comparison
/// assert_eq!(secret_a, secret_b);
/// ```
///
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct Exportable<T: Zeroize>(pub(crate) T);

// TODO: Can we implement Hex and Base64 for inner types that implement them?
// But using safe versions
impl<T: Zeroize> Exportable<T> {
    /// Create a new `Exportable` from an inner value.
    pub fn new(x: <Exportable<T> as Controlled>::Inner) -> Self
    where
        Self: Controlled,
    {
        Self::init_from_inner(x)
    }

    /// Move the inner value out without running the zeroizing `Drop`.
    /// See [`crate::move_inner_out`] for the shared primitive and rationale.
    fn into_inner_unchecked(self) -> T {
        let field: *const T = &self.0;
        // SAFETY: `field` points to `self`'s live owned inner; `Exportable`'s
        // `Drop` only zeroizes.
        unsafe { crate::move_inner_out(self, field) }
    }
}

// NOTE: no `Copy` — `Copy` and the zeroizing `Drop` are mutually exclusive.

impl<T> Clone for Exportable<T>
where
    T: Clone + Zeroize,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// PartialEq is implemented in constant time for any `Equatable` to any (nested) `Equatable`.
impl<T, O> PartialEq<O> for Exportable<T>
where
    T: Controlled,
    O: Controlled,
    <T as Controlled>::Inner: ConstantTimeEq<O::Inner>,
{
    fn eq(&self, other: &O) -> bool {
        self.risky_ref().constant_time_eq(other.risky_ref())
    }
}

impl<T: ControlledPrivate + Zeroize> ControlledPrivate for Exportable<T> {}

impl<T> Controlled for Exportable<T>
where
    T: Controlled,
{
    type Inner = T::Inner;

    fn risky_unwrap(self) -> Self::Inner {
        self.into_inner_unchecked().risky_unwrap()
    }

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x))
    }

    fn risky_ref(&self) -> &Self::Inner {
        self.0.risky_ref()
    }

    fn inner_mut(&mut self) -> &mut Self::Inner {
        self.0.inner_mut()
    }
}

impl<T, A> Extend<A> for Exportable<T>
where
    T: Extend<A> + Zeroize,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = A>,
    {
        self.0.extend(iter);
    }
}

impl<T> Serialize for Exportable<T>
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

impl<'de, T> Deserialize<'de> for Exportable<T>
where
    T: Controlled,
    T::Inner: SafeDeserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Exportable<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::safe_deserialize(deserializer).map(Exportable)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;
    use crate::{Equatable, Protected};

    #[test]
    fn test_opaque_debug() {
        let x: Exportable<Protected<[u8; 32]>> = Exportable::new([0u8; 32]);
        assert_eq!(
            format!("{x:?}"),
            "Exportable(vitaminc_protected::protected::Protected<[u8; 32]>(\"***\"))"
        );
    }

    #[test]
    fn test_serialize_deserialize() {
        fn test<T: SafeSerialize + for<'a> SafeDeserialize<'a> + Zeroize + Debug + PartialEq>(
            input: T,
        ) {
            let x: Exportable<Protected<T>> = Exportable::init_from_inner(input);
            let y = rmp_serde::to_vec(&x).unwrap();
            let z: Exportable<Protected<T>> = rmp_serde::from_slice(&y).unwrap();
            assert_eq!(z.risky_unwrap(), x.risky_unwrap());
        }

        test::<u8>(42);
        test::<u16>(42);
        test::<u32>(42);
        test::<u64>(42);
        test::<u128>(42);
        test::<i8>(42);
        test::<i16>(42);
        test::<i32>(42);
        test::<i64>(42);
        test::<i128>(42);
        test::<String>("Hello, World!".to_string());
        test::<[u8; 32]>([0; 32]);
        test::<[u8; 64]>([0; 64]);
    }

    #[test]
    fn test_serialize_deserialize_nested() {
        fn test<
            T: SafeSerialize + for<'a> SafeDeserialize<'a> + Zeroize + Debug + ConstantTimeEq,
        >(
            input: T,
        ) {
            let x: Exportable<Equatable<Protected<T>>> = Exportable::init_from_inner(input);
            let y = rmp_serde::to_vec(&x).unwrap();
            let z: Exportable<Equatable<Protected<T>>> = rmp_serde::from_slice(&y).unwrap();
            assert_eq!(z, x);
        }

        test::<u8>(42);
        test::<u16>(42);
        test::<u32>(42);
        test::<u64>(42);
        test::<u128>(42);
        test::<i8>(42);
        test::<i16>(42);
        test::<i32>(42);
        test::<i64>(42);
        test::<i128>(42);
        test::<String>("Hello, World!".to_string());
        test::<[u8; 32]>([0; 32]);
        test::<[u8; 64]>([0; 64]);
    }

    #[test]
    fn test_serialize_bytes() {
        fn test<const N: usize>() {
            let x: Exportable<Protected<[u8; N]>> = Exportable::new([0; N]);
            let y = serde_json::to_string(&x).unwrap();
            let z: Exportable<Protected<[u8; N]>> = serde_json::from_str(&y).unwrap();
            assert_eq!(z, x);
        }
        test::<1>();
        test::<2>();
        test::<4>();
        test::<16>();
        test::<32>();
        test::<64>();
    }

    #[test]
    fn test_serialize_deserialize_inner() {
        fn test<T: SafeSerialize + for<'a> SafeDeserialize<'a> + Zeroize + ConstantTimeEq>(
            input: T,
        ) {
            let x: Equatable<Exportable<Protected<T>>> = Equatable::new(input);
            let y = rmp_serde::to_vec(&x).unwrap();
            let z: Exportable<Equatable<Protected<T>>> = rmp_serde::from_slice(&y).unwrap();
            assert_eq!(z, x);
        }

        test::<u8>(42);
        test::<u16>(42);
        test::<u32>(42);
        test::<u64>(42);
        test::<u128>(42);
        test::<i8>(42);
        test::<i16>(42);
        test::<i32>(42);
        test::<i64>(42);
        test::<i128>(42);
        test::<String>("Hello, World!".to_string());
        test::<[u8; 32]>([0; 32]);
        test::<[u8; 64]>([0; 64]);
    }
}
