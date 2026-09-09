use crate::SafeRand;
use rand::CryptoRng;
use vitaminc_protected::{Controlled, Protected};

/// Bounded draws over one fixed-count Lemire reduction.
///
/// [`next_below(n)`](BoundedRng::next_below) is the primitive: a value in
/// `0..n`, the half-open bound every index-shaped use wants (`n` items, pick
/// one) and the one `std` and `rand` ranges use. It is implemented for `u32`
/// and for a [`Protected<u32>`] bound, and is also reachable as
/// [`SafeRand::next_below`] without importing this trait.
///
/// The older **inclusive** form, `0..=max`, lives on the deprecated
/// [`BoundedRngInclusive`] trait so that it can be removed later without a
/// second breaking change here.
///
/// Every draw makes exactly one 64-bit call on the generator, reduced with
/// Lemire's multiply-high method: no rejection loop and no branch on the
/// value drawn, so the number of draws does not depend on the values drawn.
/// The reduction's statistical distance from uniform is at most `n / 2⁶⁴`:
/// below 2⁻⁵⁵ for `n ≤ 256` and still at most 2⁻³² at `n = u32::MAX`. A
/// protocol that needs exact uniformity must account for that term.
pub trait BoundedRng<T> {
    /// A value in `0..n`: at least `0`, strictly below `n`, uniform to
    /// within the `n / 2⁶⁴` bias bound documented on [`BoundedRng`].
    ///
    /// # Panics
    ///
    /// Panics if `n == 0`: the range `0..0` is empty and has no value to
    /// return. Callers that compute `n` should check it first. When `n` is
    /// a [`Protected<u32>`] the panic is observable on a secret, so a caller
    /// whose secret bound may be zero must rule that out before calling.
    fn next_below(&mut self, n: T) -> T;
}

/// The older **inclusive** bounded draw, `0..=max`.
///
/// Deprecated: before cipherstash/vitaminc#198 the inclusive bound was
/// honoured only when `max` was not a power of two, so callers written
/// against either meaning were wrong for some inputs. It now does what its
/// doc always said, for every `max` up to and including `u32::MAX`, with the
/// same fixed-count draw and the same `(max + 1) / 2⁶⁴` bias bound as
/// [`BoundedRng::next_below`].
///
/// This is a separate trait rather than a deprecated method on
/// [`BoundedRng`] so that implementors of `BoundedRng` are not forced to
/// write a method they are told not to call, and so that removing it later
/// is a trait deletion rather than another breaking change to `BoundedRng`.
#[deprecated(
    note = "inclusive `0..=max`; use `BoundedRng::next_below(max + 1)`, or `next_below(n)` when you have a length `n`"
)]
pub trait BoundedRngInclusive<T> {
    /// A value in `0..=max`, uniform to within the `(max + 1) / 2⁶⁴` bias
    /// bound documented on [`BoundedRng`].
    ///
    /// The equivalent call is `BoundedRng::next_below(max + 1)` (for
    /// `max == u32::MAX` that is the whole word: use
    /// [`Rng::next_u32`](rand::Rng::next_u32)), or `next_below(n)` when the
    /// caller has a length `n` rather than a maximum.
    fn next_bounded(&mut self, max: T) -> T;
}

impl BoundedRng<u32> for SafeRand {
    fn next_below(&mut self, n: u32) -> u32 {
        below_u32(self, n)
    }
}

impl BoundedRng<Protected<u32>> for SafeRand {
    /// See [`BoundedRng::next_below`].
    ///
    /// # Panics
    ///
    /// Panics if the wrapped bound is zero. That panic is observable on a
    /// secret, so a caller whose secret bound may be zero must rule that out
    /// before calling.
    fn next_below(&mut self, n: Protected<u32>) -> Protected<u32> {
        // Check the bound before `map` unwraps it: `Controlled::map` hands
        // the raw inner value to the closure, so a zero check inside the
        // closure would panic with the secret already out of its wrapper and
        // unwinding without being wiped. Checked here, an unwind drops `n`
        // still wrapped, and `Protected`'s drop glue zeroizes it.
        assert!(*n.risky_ref() != 0, "range must be non-zero");
        n.map(|n| below_u32(self, n))
    }
}

#[allow(deprecated)]
impl BoundedRngInclusive<u32> for SafeRand {
    fn next_bounded(&mut self, max: u32) -> u32 {
        upto_u32(self, max)
    }
}

#[allow(deprecated)]
impl BoundedRngInclusive<Protected<u32>> for SafeRand {
    fn next_bounded(&mut self, max: Protected<u32>) -> Protected<u32> {
        // `0..=max` is never empty, so no pre-check is needed here.
        max.map(|max| upto_u32(self, max))
    }
}

/// A value in `0..range`, for `range >= 1`, uniform to within `range / 2⁶⁴`.
///
/// One 64-bit draw reduced with Lemire's multiply-high method. See
/// [`BoundedRng`] for the contract, including the `range / 2⁶⁴` bias bound;
/// that bound is why this helper is not exposed for ranges near `2⁶⁴`, where
/// a single 64-bit draw is no longer close to uniform.
///
/// # Panics
///
/// Panics if `range` is zero.
pub(crate) fn below_u64<R: CryptoRng>(rng: &mut R, range: u64) -> u64 {
    assert!(range > 0, "range must be non-zero");
    ((u128::from(rng.next_u64()) * u128::from(range)) >> 64) as u64
}

/// [`below_u64`] at `u32` width: a value in `0..range`.
pub(crate) fn below_u32<R: CryptoRng>(rng: &mut R, range: u32) -> u32 {
    below_u64(rng, u64::from(range)) as u32
}

/// The inclusive form, a value in `0..=max`, for every `max` including
/// `u32::MAX`: `max + 1` always fits a `u64`, so the sampler sees the full
/// inclusive range without overflow. Every inclusive entry point routes
/// through here so the edge is handled exactly once.
pub(crate) fn upto_u32<R: CryptoRng>(rng: &mut R, max: u32) -> u32 {
    below_u64(rng, u64::from(max) + 1) as u32
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use rand::TryCryptoRng;

    use super::{below_u32, upto_u32};

    /// Yields one fixed word, so the reduction can be pinned to exact
    /// outputs at the ends and the midpoint of the draw space.
    struct FixedDraw(u64);
    impl rand::TryRng for FixedDraw {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0 as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.0)
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }
    impl TryCryptoRng for FixedDraw {}

    // These tests drive the same `below_u32` / `upto_u32` helpers that every
    // `BoundedRng` impl and `next_bounded_u32` call, so a regression in the
    // reduction cannot hide behind a test-only copy of it.

    #[test]
    fn min_draw_maps_to_zero() {
        assert_eq!(0, upto_u32(&mut FixedDraw(0), 9));
        assert_eq!(0, below_u32(&mut FixedDraw(0), 10));
    }

    #[test]
    fn max_draw_maps_to_the_top_of_the_range() {
        // Inclusive: the bound itself is the top value. `31` is the case the
        // old power-of-two branch could never return.
        assert_eq!(9, upto_u32(&mut FixedDraw(u64::MAX), 9));
        assert_eq!(31, upto_u32(&mut FixedDraw(u64::MAX), 31));
        assert_eq!(32, upto_u32(&mut FixedDraw(u64::MAX), 32));
        // Half-open: the bound is excluded.
        assert_eq!(9, below_u32(&mut FixedDraw(u64::MAX), 10));
        assert_eq!(31, below_u32(&mut FixedDraw(u64::MAX), 32));
    }

    #[test]
    fn midpoint_draw_maps_to_half_range() {
        assert_eq!(5, upto_u32(&mut FixedDraw(1 << 63), 9));
        assert_eq!(5, below_u32(&mut FixedDraw(1 << 63), 10));
    }

    #[test]
    fn a_bound_of_zero_is_always_zero_inclusively() {
        // `0..=0` has one value; `0..0` has none.
        assert_eq!(0, upto_u32(&mut FixedDraw(u64::MAX), 0));
        assert_eq!(0, below_u32(&mut FixedDraw(u64::MAX), 1));
    }

    #[test]
    #[should_panic(expected = "range must be non-zero")]
    fn an_empty_half_open_range_panics() {
        below_u32(&mut FixedDraw(0), 0);
    }

    #[test]
    fn max_of_u32_max_covers_the_whole_word() {
        assert_eq!(u32::MAX, upto_u32(&mut FixedDraw(u64::MAX), u32::MAX));
        assert_eq!(0, upto_u32(&mut FixedDraw(0), u32::MAX));
    }

    #[test]
    fn a_zero_protected_bound_panics_before_it_is_unwrapped() {
        use crate::SafeRand;
        use rand::SeedableRng;
        use vitaminc_protected::Protected;

        // Pins the behaviour documented on the `Protected<u32>` impl: a
        // zero secret bound panics, and it panics before `map` unwraps the
        // value, so the generator is never called.
        let mut rng = SafeRand::from_seed([5u8; 32]);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Protected<u32> = rng.next_below(Protected::new(0));
        }));
        let msg = caught.expect_err("a zero bound must panic");
        let msg = msg
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| msg.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(msg.contains("range must be non-zero"), "{msg}");
        // No draw was spent on the failed call.
        let mut untouched = SafeRand::from_seed([5u8; 32]);
        assert_eq!(untouched.next_below(1000), rng.next_below(1000));
    }

    #[test]
    fn trait_impls_route_through_the_shared_helpers() {
        use super::BoundedRng;
        #[allow(deprecated)]
        use super::BoundedRngInclusive;
        use crate::SafeRand;
        use rand::SeedableRng;
        use vitaminc_protected::{Controlled, Protected};

        // The plain and `Protected<u32>` impls, and the inherent
        // `SafeRand::next_below`, must all be the same draw and reduction as
        // the helpers over the same seed: not a constant, not a differently
        // reduced value, and one draw per call.
        let mut helper = SafeRand::from_seed([5u8; 32]);
        let mut plain = SafeRand::from_seed([5u8; 32]);
        let mut protected = SafeRand::from_seed([5u8; 32]);
        let mut inherent = SafeRand::from_seed([5u8; 32]);
        for _ in 0..100 {
            let want = below_u32(&mut helper, 1000);
            assert_eq!(want, BoundedRng::next_below(&mut plain, 1000u32));
            let p: Protected<u32> = protected.next_below(Protected::new(1000));
            assert_eq!(want, p.risky_unwrap());
            assert_eq!(want, inherent.next_below(1000));
        }

        #[allow(deprecated)]
        for _ in 0..100 {
            let want = upto_u32(&mut helper, 999);
            assert_eq!(want, plain.next_bounded(999u32));
            let p: Protected<u32> = protected.next_bounded(Protected::new(999));
            assert_eq!(want, p.risky_unwrap());
            assert_eq!(want, inherent.next_bounded_u32(999));
        }
    }
}
