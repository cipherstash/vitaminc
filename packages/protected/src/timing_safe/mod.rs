//! Timing safe equality checks for sensitive values.
//! 
//! 
use subtle::ConstantTimeEq;
pub use protected_derive::TimingSafe;

pub trait TimingSafeEq {
    /// Must be constant-time with respect to secret data.
    fn ts_eq(&self, other: &Self) -> subtle::Choice;

    fn ts_ne(&self, other: &Self) -> subtle::Choice {
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

impl<T, const N: usize> TimingSafeEq for [T; N] where [T]: TimingSafeEq {
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