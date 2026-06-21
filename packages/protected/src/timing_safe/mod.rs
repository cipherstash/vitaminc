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
/// or via blanket impls (e.g., for arrays).
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
/// * The derive works with generics and const generics; your field types must still satisfy `TimingSafeEq`.
///
pub trait TimingSafeEq {
    /// Must be constant-time with respect to secret data.
    fn ts_eq(&self, other: &Self) -> Choice;

    fn ts_ne(&self, other: &Self) -> Choice {
        !self.ts_eq(other)
    }
}

impl TimingSafeEq for &str {
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
}
