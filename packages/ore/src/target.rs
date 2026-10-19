//! Targets a caller names when the program is compiled, and the tables
//! that say what fits them.
//!
//! An order space declares the type every value in it is encoded as: its
//! target. [`OrderTarget`] names one while the program runs, as an index
//! layer that reads its column types from a schema must. The zero-sized
//! markers here name one when the program is compiled, so the compiler can
//! check what goes in: [`FitsIn`] lists the conversions that never lose
//! information, and [`OwnTarget`] gives a Rust type the target it is.
//! Both are sealed tables, generated in this module, so no caller can add
//! a conversion that might be refused or infer a target from a value.
//!
//! The same method takes either: [`OrderEncrypt::target`] is generic over
//! [`Target`], which every marker and [`OrderTarget`] implement.
//!
//! [`OrderEncrypt::target`]: crate::OrderEncrypt::target

use core::fmt;

use vitaminc_aead::{Bytes as RawBytes, Encrypt};

use crate::{OrderScheme, OrderTarget};

mod private {
    /// Seals [`Target`](super::Target), [`FitsIn`](super::FitsIn) and
    /// [`OwnTarget`](super::OwnTarget) to this crate.
    pub trait Sealed {}
}

/// A target an order space can be opened with: one of the zero-sized
/// markers in this module, named when the program is compiled, or an
/// [`OrderTarget`], chosen while it runs.
///
/// Sealed: every target is one this crate encodes.
pub trait Target: private::Sealed + Copy + fmt::Debug {
    /// The target as the value every encoding is keyed by.
    fn runtime(self) -> OrderTarget;
}

/// A target known when the program is compiled: one of the markers in this
/// module. What a space of such a target takes is checked by the compiler,
/// through [`FitsIn`].
pub trait StaticTarget: Target + Default {
    /// The target this marker stands for.
    const TARGET: OrderTarget;
}

impl private::Sealed for OrderTarget {}

impl Target for OrderTarget {
    fn runtime(self) -> OrderTarget {
        self
    }
}

/// A value that always fits target `T`: the conversion loses nothing and
/// the encoding refuses nothing, so [`OrderSpace::encrypt`] can take it
/// without a value-refusal arm in its error.
///
/// A sealed table, one impl per conversion:
///
/// | Target | Takes |
/// | --- | --- |
/// | an integer target | every integer type whose whole range it holds, so `I32` takes `i8`, `i16`, `i32` and `u16` (a `u8` is not a scalar of the data model: `Vec<u8>` is bytes) |
/// | `F64` | `f32`, `f64` |
/// | `Bytes` | `&[u8]`, `Vec<u8>`, `[u8; N]`, [`Bytes`](vitaminc_aead::Bytes) |
/// | `Date` | `chrono::NaiveDate` (feature `chrono`) |
/// | `Timestamp` | `vitaminc_aead::Timestamp` (feature `chrono`) |
/// | `Decimal` | `rust_decimal::Decimal` (feature `rust_decimal`) |
/// | `Uuid` | `uuid::Uuid` (feature `uuid`) |
///
/// and a reference to any of them. What is not here can be refused: an
/// `i64` may not fit `I32`, text may hold a code point Unicode 16 does not
/// assign, and a `chrono::DateTime<Utc>` may be a leap second. Those go
/// through [`OrderSpace::encrypt_checked`], which checks the value while
/// the program runs.
///
/// [`OrderSpace::encrypt`]: crate::OrderSpace::encrypt
/// [`OrderSpace::encrypt_checked`]: crate::OrderSpace::encrypt_checked
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a value that always fits `{T}`",
    label = "does not always fit `{T}`",
    note = "`encrypt` takes a value the encoding never refuses: a narrower integer, an `f32`, bytes, or a typed value such as a `NaiveDate`",
    note = "a value the encoding can refuse (an integer that may be out of range, text, a `DateTime<Utc>`, or any other `Encrypt` value) goes through `encrypt_checked`, which checks it while the program runs"
)]
pub trait FitsIn<T: StaticTarget>: Encrypt + private::Sealed {}

/// A Rust type's own target, for [`OrderEncrypt::encrypt`] and the other
/// chains that name none: an `i64` is an `I64`, an `f32` an `F64`, a
/// `&str` a `Text`.
///
/// Sealed, and implemented for the data model's own types only. A target
/// is never inferred from a value: a JavaScript `BigInt` arrives as the
/// narrowest integer that holds it, and inferring from the value would
/// scatter one index across several domains. A newtype names its target
/// with [`OrderEncrypt::target`].
///
/// [`OrderEncrypt::encrypt`]: crate::OrderEncrypt::encrypt
/// [`OrderEncrypt::target`]: crate::OrderEncrypt::target
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no order target of its own",
    label = "has no order target of its own",
    note = "name the target: `scheme.target(I64).encrypt_checked(value)`"
)]
pub trait OwnTarget: Encrypt + private::Sealed {
    /// The target this type is.
    type Target: StaticTarget;
}

/// What a scheme takes: implemented by a scheme crate for every target
/// its scheme encrypts, so that `scheme.target(Text)` on a fixed-width
/// scheme fails to compile rather than returning
/// [`OrderError::Unsupported`](crate::OrderError::Unsupported).
///
/// A scheme answers twice. `Supports<OrderTarget>` is required of every
/// scheme (no space of any target opens without it), and its
/// [`supports`](Self::supports) says which targets the scheme takes when
/// one is chosen while the program runs. `Supports<I32>` and the other
/// marker impls say the same when the target is named as the program is
/// compiled. A scheme writes both at once with
/// [`supports_targets!`](crate::supports_targets), from one list, so
/// they cannot disagree; a scheme that takes every target writes
/// [`supports_every_target!`](crate::supports_every_target). A space
/// asks the runtime answer for every target it is opened with, and in a
/// debug build asserts that a marker's answer agrees.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no order term for `{T}`",
    label = "does not implement `Supports<{T}>`",
    note = "a scheme lists the targets it takes with `vitaminc_ore::supports_targets!(Scheme; I32, Date)`, which answers for each marker and for `OrderTarget`; pick one it lists, or an `OrderTarget` chosen while the program runs"
)]
pub trait Supports<T: Target>: OrderScheme {
    /// Whether the scheme takes terms of `target`. For a marker, `true`
    /// (the impl exists); for an [`OrderTarget`], the scheme's list.
    fn supports(target: T) -> bool;
}

/// Implement [`Supports`] for the targets a scheme takes, from one list:
/// once for [`OrderTarget`], answering `true` for a listed target, and
/// once per listed marker.
///
/// ```
/// # use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
/// # struct TenBytes;
/// # impl OrderScheme for TenBytes {
/// #     const NAME: &'static str = "ten-bytes";
/// #     type Term = Vec<u8>;
/// #     type Error = core::convert::Infallible;
/// #     type Space = ();
/// #     fn open(&self, _: vitaminc_ore::OrderTarget, _: &Context<'_>) -> Result<(), Self::Error> {
/// #         Ok(())
/// #     }
/// #     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
/// #         use vitaminc_protected::Controlled;
/// #         Ok(p.bytes().risky_ref().clone())
/// #     }
/// #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> { Some(a.cmp(b)) }
/// # }
/// // A fixed-width scheme over at most ten bytes.
/// vitaminc_ore::supports_targets!(TenBytes; I8, U8, I16, U16, I32, U32, I64, U64, F64, Date);
/// ```
#[macro_export]
macro_rules! supports_targets {
    ($scheme:ty; $($marker:ident),* $(,)?) => {
        impl $crate::Supports<$crate::OrderTarget> for $scheme {
            fn supports(target: $crate::OrderTarget) -> bool {
                #[allow(unreachable_patterns)]
                match target {
                    $($crate::OrderTarget::$marker => true,)*
                    _ => false,
                }
            }
        }
        $(
            impl $crate::Supports<$crate::target::$marker> for $scheme {
                fn supports(_: $crate::target::$marker) -> bool {
                    true
                }
            }
        )*
    };
}

/// Implement [`Supports`] for every target, for a scheme that takes them
/// all, as the CLLW schemes do: [`supports_targets!`] with the full list.
///
/// ```
/// # use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
/// # struct Cllw;
/// # impl OrderScheme for Cllw {
/// #     const NAME: &'static str = "cllw";
/// #     type Term = Vec<u8>;
/// #     type Error = core::convert::Infallible;
/// #     type Space = ();
/// #     fn open(&self, _: vitaminc_ore::OrderTarget, _: &Context<'_>) -> Result<(), Self::Error> {
/// #         Ok(())
/// #     }
/// #     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
/// #         use vitaminc_protected::Controlled;
/// #         Ok(p.bytes().risky_ref().clone())
/// #     }
/// #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<core::cmp::Ordering> { Some(a.cmp(b)) }
/// # }
/// vitaminc_ore::supports_every_target!(Cllw);
/// ```
#[macro_export]
macro_rules! supports_every_target {
    ($scheme:ty) => {
        $crate::supports_targets!($scheme;
            I8, U8, I16, U16, I32, U32, I64, U64, I128, U128,
            F64, Date, Timestamp, Decimal, Text, Bytes, Uuid);
    };
}

/// One marker per target, each a zero-sized `Copy` type that stands for
/// its [`OrderTarget`] variant.
macro_rules! markers {
    ($($(#[$doc:meta])* $marker:ident),* $(,)?) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
            pub struct $marker;

            impl private::Sealed for $marker {}

            impl Target for $marker {
                fn runtime(self) -> OrderTarget {
                    OrderTarget::$marker
                }
            }

            impl StaticTarget for $marker {
                const TARGET: OrderTarget = OrderTarget::$marker;
            }
        )*
    };
}

markers! {
    /// [`OrderTarget::I8`].
    I8,
    /// [`OrderTarget::U8`].
    U8,
    /// [`OrderTarget::I16`].
    I16,
    /// [`OrderTarget::U16`].
    U16,
    /// [`OrderTarget::I32`].
    I32,
    /// [`OrderTarget::U32`].
    U32,
    /// [`OrderTarget::I64`].
    I64,
    /// [`OrderTarget::U64`].
    U64,
    /// [`OrderTarget::I128`].
    I128,
    /// [`OrderTarget::U128`].
    U128,
    /// [`OrderTarget::F64`].
    F64,
    /// [`OrderTarget::Date`].
    Date,
    /// [`OrderTarget::Timestamp`].
    Timestamp,
    /// [`OrderTarget::Decimal`].
    Decimal,
    /// [`OrderTarget::Text`].
    Text,
    /// [`OrderTarget::Bytes`].
    Bytes,
    /// [`OrderTarget::Uuid`].
    Uuid,
}

/// Seal the value types the tables below name, by value and by reference.
macro_rules! sealed {
    ($($ty:ty),* $(,)?) => {
        $(
            impl private::Sealed for $ty {}
            impl private::Sealed for &$ty {}
        )*
    };
}

/// `FitsIn` rows: each target, then every type that always fits it, by
/// value and by reference.
macro_rules! fits {
    ($($target:ident: $($ty:ty),*;)*) => {
        $($(
            impl FitsIn<$target> for $ty {}
            impl FitsIn<$target> for &$ty {}
        )*)*
    };
}

/// `OwnTarget` rows: a type and the target it is, by value and by
/// reference.
macro_rules! own {
    ($($ty:ty => $target:ident),* $(,)?) => {
        $(
            impl OwnTarget for $ty {
                type Target = $target;
            }
            impl OwnTarget for &$ty {
                type Target = $target;
            }
        )*
    };
}

sealed!(
    i8,
    i16,
    u16,
    i32,
    u32,
    i64,
    u64,
    i128,
    u128,
    f32,
    f64,
    str,
    String,
    [u8],
    Vec<u8>,
);

impl private::Sealed for RawBytes<'_> {}
impl private::Sealed for &RawBytes<'_> {}
impl<const N: usize> private::Sealed for [u8; N] {}
impl<const N: usize> private::Sealed for &[u8; N] {}

// An integer target takes every integer type whose whole range it holds:
// a signed target holds a narrower type of either sign, an unsigned
// target only a narrower unsigned one. There is no `u8` row: a `u8` is
// not a scalar of the data model (a `Vec<u8>` is bytes), so it has no
// `Encrypt` impl to fit with.
fits! {
    I8: i8;
    I16: i8, i16;
    U16: u16;
    I32: i8, i16, i32, u16;
    U32: u16, u32;
    I64: i8, i16, i32, i64, u16, u32;
    U64: u16, u32, u64;
    I128: i8, i16, i32, i64, i128, u16, u32, u64;
    U128: u16, u32, u64, u128;
    F64: f32, f64;
    Bytes: Vec<u8>;
}

impl FitsIn<Bytes> for &[u8] {}
impl FitsIn<Bytes> for RawBytes<'_> {}
impl FitsIn<Bytes> for &RawBytes<'_> {}
impl<const N: usize> FitsIn<Bytes> for [u8; N] {}
impl<const N: usize> FitsIn<Bytes> for &[u8; N] {}

own! {
    i8 => I8,
    i16 => I16,
    u16 => U16,
    i32 => I32,
    u32 => U32,
    i64 => I64,
    u64 => U64,
    i128 => I128,
    u128 => U128,
    f32 => F64,
    f64 => F64,
    String => Text,
    Vec<u8> => Bytes,
}

impl OwnTarget for &str {
    type Target = Text;
}
impl OwnTarget for &[u8] {
    type Target = Bytes;
}
impl OwnTarget for RawBytes<'_> {
    type Target = Bytes;
}
impl OwnTarget for &RawBytes<'_> {
    type Target = Bytes;
}
impl<const N: usize> OwnTarget for [u8; N] {
    type Target = Bytes;
}
impl<const N: usize> OwnTarget for &[u8; N] {
    type Target = Bytes;
}

// The typed values callers hold. Each is inside the range its encoding
// takes for every value the type can hold: chrono's `NaiveDate` spans
// exactly the day range `Logical::Date` admits, a `Timestamp` is never a
// leap second and lies in chrono's range, and a `rust_decimal::Decimal`
// has a 96-bit mantissa and a scale of at most 28, which is what the
// decimal encoding takes. A `chrono::DateTime<Utc>` may be a leap second,
// which has no count, so it is checked, not fitting.
#[cfg(feature = "chrono")]
mod chrono_rows {
    use super::*;
    use chrono::{DateTime, NaiveDate, Utc};
    use vitaminc_aead::Timestamp as Instant;

    impl private::Sealed for NaiveDate {}
    impl private::Sealed for &NaiveDate {}
    impl private::Sealed for DateTime<Utc> {}
    impl private::Sealed for &DateTime<Utc> {}
    impl private::Sealed for Instant {}
    impl private::Sealed for &Instant {}

    impl FitsIn<Date> for NaiveDate {}
    impl FitsIn<Date> for &NaiveDate {}
    impl FitsIn<Timestamp> for Instant {}
    impl FitsIn<Timestamp> for &Instant {}

    impl OwnTarget for NaiveDate {
        type Target = Date;
    }
    impl OwnTarget for &NaiveDate {
        type Target = Date;
    }
    impl OwnTarget for DateTime<Utc> {
        type Target = Timestamp;
    }
    impl OwnTarget for &DateTime<Utc> {
        type Target = Timestamp;
    }
    impl OwnTarget for Instant {
        type Target = Timestamp;
    }
    impl OwnTarget for &Instant {
        type Target = Timestamp;
    }
}

#[cfg(feature = "rust_decimal")]
mod decimal_rows {
    use super::*;

    impl private::Sealed for rust_decimal::Decimal {}
    impl private::Sealed for &rust_decimal::Decimal {}
    impl FitsIn<Decimal> for rust_decimal::Decimal {}
    impl FitsIn<Decimal> for &rust_decimal::Decimal {}
    impl OwnTarget for rust_decimal::Decimal {
        type Target = Decimal;
    }
    impl OwnTarget for &rust_decimal::Decimal {
        type Target = Decimal;
    }
}

#[cfg(feature = "uuid")]
mod uuid_rows {
    use super::*;

    impl private::Sealed for uuid::Uuid {}
    impl private::Sealed for &uuid::Uuid {}
    impl FitsIn<Uuid> for uuid::Uuid {}
    impl FitsIn<Uuid> for &uuid::Uuid {}
    impl OwnTarget for uuid::Uuid {
        type Target = Uuid;
    }
    impl OwnTarget for &uuid::Uuid {
        type Target = Uuid;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_marker_stands_for_its_target_and_every_target_is_itself() {
        fn check<T: StaticTarget>(expected: OrderTarget) {
            assert_eq!(T::TARGET, expected);
            assert_eq!(T::default().runtime(), expected);
        }
        check::<I8>(OrderTarget::I8);
        check::<U8>(OrderTarget::U8);
        check::<I16>(OrderTarget::I16);
        check::<U16>(OrderTarget::U16);
        check::<I32>(OrderTarget::I32);
        check::<U32>(OrderTarget::U32);
        check::<I64>(OrderTarget::I64);
        check::<U64>(OrderTarget::U64);
        check::<I128>(OrderTarget::I128);
        check::<U128>(OrderTarget::U128);
        check::<F64>(OrderTarget::F64);
        check::<Date>(OrderTarget::Date);
        check::<Timestamp>(OrderTarget::Timestamp);
        check::<Decimal>(OrderTarget::Decimal);
        check::<Text>(OrderTarget::Text);
        check::<Bytes>(OrderTarget::Bytes);
        check::<Uuid>(OrderTarget::Uuid);
        for target in OrderTarget::ALL {
            assert_eq!(target.runtime(), *target);
        }
    }
}
