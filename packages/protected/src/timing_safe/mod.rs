pub use subtle::Choice;
use subtle::ConstantTimeEq;

/// This module defines the [`TimingSafeEq`] trait for performing equality
/// checks in constant-time with respect to secret data, and the
/// [`TimingSafeEq`] derive macro to automatically implement it for structs and enums.
///
/// ## Overview
///
/// * [`TimingSafeEq`] – compare two values in constant-time, returning a
///   [`Choice`] instead of a `bool`.
/// * [`TimingSafeEq`] – derive macro that implements [`TimingSafeEq`] and
///   [`PartialEq`]/[`Eq`] by combining all fields’ `ts_eq` results with bitwise AND.
///
/// The derive requires that all fields of the type implement
/// [`TimingSafeEq`], which you can do manually for your own field types
/// or via blanket impls (e.g., for arrays and references).
///
/// Implementations are provided for the integer primitives, `bool`, `f32` and
/// `f64` (bit-pattern equality, see the impl docs), `str`, `String`, `[u8]`,
/// `Vec<u8>`, `[T; N]`, and `&T` for any `T: TimingSafeEq`.
///
/// The variable-length impls (`str`, `String`, `[u8]`, `Vec<u8>`) report a
/// length mismatch as unequal without comparing contents, as `subtle`'s
/// slice comparison does, so a length is never treated as secret.
///
/// Implementations of [`TimingSafeEq`] for many common types are included and internally use the [subtle](https://crates.io/crates/subtle) crate.
///
/// ## Examples
///
/// ### Implementing `TimingSafeEq` manually
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{TimingSafeEq, Choice};
///
/// #[derive(Clone, Copy)]
/// struct CtU8(u8);
///
/// impl TimingSafeEq for CtU8 {
///     fn ts_eq(&self, other: &Self) -> Choice {
///         // Branchless equality: (x ^ y) == 0
///         let x = self.0 ^ other.0;
///         Choice::from((x == 0) as u8)
///     }
/// }
/// ```
///
/// ### Using `#[derive(TimingSafeEq)]`
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{TimingSafeEq, Choice};
///
/// #[derive(TimingSafeEq)]
/// struct Key<const N: usize>([u8; N]);
///
/// let k1 = Key::<3>([1, 2, 3]);
/// let k2 = Key::<3>([1, 2, 3]);
/// let k3 = Key::<3>([1, 2, 4]);
///
/// assert!(k1 == k2); // uses constant-time compare internally
/// assert!(bool::from(k1.ts_eq(&k2)));
///
/// assert!(k1 != k3);
/// assert!(!bool::from(k1.ts_eq(&k3)));
/// ```
///
/// ## Notes
///
/// * The derive performs a field-wise AND of all `ts_eq` results; if any field differs, the result is `Choice(0)`.
/// * All fields must implement `TimingSafeEq`, or the derive will fail to compile.
/// * `PartialEq`/`Eq` are implemented in terms of `ts_eq` and return `bool`.
/// * Do not derive `PartialOrd` or `Ord` from std beside this derive on a type
///   with `f32` or `f64` fields. The derived `PartialEq` is bit-pattern
///   equality (see the float impls), while std's `PartialOrd` for floats is
///   IEEE ordering, so `a == b` would not imply `partial_cmp(a, b) ==
///   Some(Equal)` (two equal `NaN`s, or `0.0` and `-0.0`), which `PartialOrd`
///   requires. Nothing warns about it. Write the ordering by hand if the type
///   needs one.
/// * The derive works with generics and const generics; your field types must still satisfy `TimingSafeEq`.
///
pub trait TimingSafeEq {
    /// Must be constant-time with respect to secret data.
    fn ts_eq(&self, other: &Self) -> Choice;

    fn ts_ne(&self, other: &Self) -> Choice {
        !self.ts_eq(other)
    }
}

/// Forwards to `T`, so a reference compares exactly as the value it points at.
///
/// This is what lets `#[derive(TimingSafeEq)]` handle borrowed fields such as
/// `&'a str` and `&'a [u8]`: the derive compares fields by reference, so a
/// `&'a [u8]` field is compared as `&&[u8]`, which needs `&[u8]: TimingSafeEq`.
///
/// A blanket impl is a one-way door (a downstream crate can no longer write
/// its own `impl TimingSafeEq for &Theirs`), which is why there is no `&mut T`
/// impl: nothing needs one yet.
impl<T: TimingSafeEq + ?Sized> TimingSafeEq for &T {
    fn ts_eq(&self, other: &Self) -> Choice {
        T::ts_eq(*self, *other)
    }
}

/// Compares the UTF-8 bytes in constant time.
impl TimingSafeEq for str {
    fn ts_eq(&self, other: &Self) -> subtle::Choice {
        subtle::ConstantTimeEq::ct_eq(self.as_bytes(), other.as_bytes())
    }
}

impl TimingSafeEq for String {
    fn ts_eq(&self, other: &Self) -> subtle::Choice {
        subtle::ConstantTimeEq::ct_eq(self.as_bytes(), other.as_bytes())
    }
}

impl TimingSafeEq for [u8] {
    fn ts_eq(&self, other: &Self) -> subtle::Choice {
        subtle::ConstantTimeEq::ct_eq(self, other)
    }
}

impl TimingSafeEq for Vec<u8> {
    fn ts_eq(&self, other: &Self) -> subtle::Choice {
        subtle::ConstantTimeEq::ct_eq(self.as_slice(), other.as_slice())
    }
}

impl<T, const N: usize> TimingSafeEq for [T; N]
where
    [T]: TimingSafeEq,
{
    fn ts_eq(&self, other: &Self) -> subtle::Choice {
        TimingSafeEq::ts_eq(self.as_slice(), other.as_slice())
    }
}

macro_rules! impl_timing_safe_eq {
    ($($type:ty),+) => {
        $(
            impl TimingSafeEq for $type {
                fn ts_eq(&self, other: &Self) -> subtle::Choice {
                    self.ct_eq(other)
                }
            }
        )+
    };
}

impl_timing_safe_eq!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

/// Compares the two booleans as `u8` (`0` or `1`) in constant time.
impl TimingSafeEq for bool {
    fn ts_eq(&self, other: &Self) -> Choice {
        (*self as u8).ct_eq(&(*other as u8))
    }
}

/// Bit-pattern equality, **not** IEEE 754 `==`.
///
/// The two values are equal when [`f32::to_bits`] returns the same `u32` for
/// both, compared in constant time. This differs from `==` in two places:
///
/// * a `NaN` equals itself (and any `NaN` with the same sign and payload),
///   whereas `NaN == NaN` is `false`; two `NaN`s with different payloads are
///   unequal;
/// * `-0.0` and `0.0` are unequal, whereas `-0.0 == 0.0` is `true`.
///
/// Bit-pattern equality is the only definition that is both constant time and
/// well defined for every value: IEEE `==` needs data-dependent special cases
/// for `NaN` and signed zero, and is not reflexive, so it cannot back
/// [`Eq`]. It is also what a sealed float needs, since the bits are what gets
/// encrypted, and two floats that encrypt from different bits are different
/// plaintexts.
///
/// Because of this, do not derive `PartialOrd` or `Ord` from std on a type
/// whose `PartialEq` comes from `#[derive(TimingSafeEq)]` and holds a float:
/// std's float ordering is IEEE, so `a == b` would not imply
/// `partial_cmp(a, b) == Some(Equal)`.
impl TimingSafeEq for f32 {
    fn ts_eq(&self, other: &Self) -> Choice {
        self.to_bits().ct_eq(&other.to_bits())
    }
}

/// Bit-pattern equality, **not** IEEE 754 `==`.
///
/// The two values are equal when [`f64::to_bits`] returns the same `u64` for
/// both, compared in constant time. This differs from `==` in two places:
///
/// * a `NaN` equals itself (and any `NaN` with the same sign and payload),
///   whereas `NaN == NaN` is `false`; two `NaN`s with different payloads are
///   unequal;
/// * `-0.0` and `0.0` are unequal, whereas `-0.0 == 0.0` is `true`.
///
/// Bit-pattern equality is the only definition that is both constant time and
/// well defined for every value: IEEE `==` needs data-dependent special cases
/// for `NaN` and signed zero, and is not reflexive, so it cannot back
/// [`Eq`]. It is also what a sealed float needs, since the bits are what gets
/// encrypted, and two floats that encrypt from different bits are different
/// plaintexts.
///
/// Because of this, do not derive `PartialOrd` or `Ord` from std on a type
/// whose `PartialEq` comes from `#[derive(TimingSafeEq)]` and holds a float:
/// std's float ordering is IEEE, so `a == b` would not imply
/// `partial_cmp(a, b) == Some(Equal)`.
impl TimingSafeEq for f64 {
    fn ts_eq(&self, other: &Self) -> Choice {
        self.to_bits().ct_eq(&other.to_bits())
    }
}

#[cfg(test)]
mod tests {
    use super::TimingSafeEq;

    // `ts_ne` is the negation of `ts_eq`; without this, deleting the `!` in the
    // default impl (so `ts_ne` == `ts_eq`) goes unnoticed. See issue #207.
    #[test]
    fn ts_ne_negates_ts_eq() {
        let a: u8 = 5;
        let equal: u8 = 5;
        let different: u8 = 6;

        // Equal values: ts_eq true, ts_ne false.
        assert!(bool::from(a.ts_eq(&equal)));
        assert!(!bool::from(a.ts_ne(&equal)));

        // Different values: ts_eq false, ts_ne true.
        assert!(!bool::from(a.ts_eq(&different)));
        assert!(bool::from(a.ts_ne(&different)));
    }

    fn eq<T: TimingSafeEq + ?Sized>(a: &T, b: &T) -> bool {
        bool::from(a.ts_eq(b))
    }

    #[test]
    fn bool_compares_by_value() {
        assert!(eq(&true, &true));
        assert!(eq(&false, &false));
        assert!(!eq(&true, &false));
        assert!(!eq(&false, &true));
    }

    #[test]
    fn f32_is_bit_pattern_equality() {
        assert!(eq(&1.5f32, &1.5f32));
        assert!(!eq(&1.5f32, &2.5f32));

        // Same NaN bits are equal, unlike IEEE `==`.
        let nan = f32::NAN;
        assert!(eq(&nan, &nan));

        // NaNs with different payloads are unequal.
        let other_nan = f32::from_bits(nan.to_bits() ^ 1);
        assert!(other_nan.is_nan());
        assert!(!eq(&nan, &other_nan));

        // Signed zeros are unequal, unlike IEEE `==`.
        assert!(!eq(&-0.0f32, &0.0f32));
        assert!(eq(&-0.0f32, &-0.0f32));
    }

    #[test]
    fn f64_is_bit_pattern_equality() {
        assert!(eq(&1.5f64, &1.5f64));
        assert!(!eq(&1.5f64, &2.5f64));

        let nan = f64::NAN;
        assert!(eq(&nan, &nan));

        let other_nan = f64::from_bits(nan.to_bits() ^ 1);
        assert!(other_nan.is_nan());
        assert!(!eq(&nan, &other_nan));

        assert!(!eq(&-0.0f64, &0.0f64));
        assert!(eq(&-0.0f64, &-0.0f64));
    }

    #[test]
    fn str_compares_bytes() {
        assert!(eq("abc", "abc"));
        assert!(!eq("abc", "abd"));
        assert!(!eq("abc", "abcd"));
    }

    #[test]
    fn shared_reference_forwards() {
        let a: &[u8] = &[1, 2, 3];
        let b: &[u8] = &[1, 2, 3];
        let c: &[u8] = &[1, 2, 4];
        let d: &[u8] = &[1, 2];
        assert!(eq(&a, &b));
        assert!(!eq(&a, &c));
        assert!(!eq(&a, &d));

        assert!(eq(&"abc", &"abc"));
        assert!(!eq(&"abc", &"abd"));
    }
}
