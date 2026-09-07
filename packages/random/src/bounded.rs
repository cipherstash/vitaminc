use crate::{safe_rand::below, SafeRand};
use rand::CryptoRng;
use vitaminc_protected::{Controlled, Protected};

/// A trait for generating random numbers within a specific range.
///
/// `next_bounded(max)` is **inclusive**: uniform in `0..=max`. For the more
/// common index-shaped bound, `0..n`, use [`SafeRand::next_below`].
pub trait BoundedRng<T> {
    fn next_bounded(&mut self, max: T) -> T;
}

impl BoundedRng<u32> for SafeRand {
    fn next_bounded(&mut self, max: u32) -> u32 {
        next_bounded_u32(self, max)
    }
}

impl BoundedRng<Protected<u32>> for SafeRand {
    fn next_bounded(&mut self, max: Protected<u32>) -> Protected<u32> {
        max.map(|max| next_bounded_u32(self, max))
    }
}

impl BoundedRng<usize> for SafeRand {
    fn next_bounded(&mut self, _max: usize) -> usize {
        unimplemented!()
    }
}

/// Uniform in `0..=max`, for any `max`: one sampler for the crate, so this
/// and [`SafeRand::next_below`] cannot drift (cipherstash/vitaminc#321).
fn next_bounded_u32<R: CryptoRng>(rng: &mut R, max: u32) -> u32 {
    below(rng, u64::from(max) + 1)
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use rand::TryCryptoRng;

    use super::{next_bounded_u32, BoundedRng};

    /// Replays a fixed sequence of 32-bit outputs, so a test can script a
    /// rejection and see what is accepted after it.
    struct TestBoundedRand(std::collections::VecDeque<u32>);

    impl TestBoundedRand {
        fn new(outputs: impl IntoIterator<Item = u32>) -> Self {
            Self(outputs.into_iter().collect())
        }
    }

    impl rand::TryRng for TestBoundedRand {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0.pop_front().expect("scripted outputs exhausted"))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.try_next_u32()?))
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
            unimplemented!()
        }
    }
    impl TryCryptoRng for TestBoundedRand {}

    impl BoundedRng<u32> for TestBoundedRand {
        fn next_bounded(&mut self, max: u32) -> u32 {
            next_bounded_u32(self, max)
        }
    }

    // `next_bounded(10)` keeps the low 4 bits (0..=10 needs 11 values, next
    // power of two 16) and rejects 11..=15.
    #[test]
    fn non_power_of_two_bound_masks_and_accepts_in_range() {
        assert_eq!(8, TestBoundedRand::new([8]).next_bounded(10));
        // 25 & 15 == 9, accepted without a retry.
        assert_eq!(9, TestBoundedRand::new([25]).next_bounded(10));
    }

    #[test]
    fn non_power_of_two_bound_rejects_and_retries() {
        // 27 & 15 == 11 > 10: rejected; 3 accepted.
        assert_eq!(3, TestBoundedRand::new([27, 3]).next_bounded(10));
    }

    // `next_bounded(32)` is inclusive, so 32 itself is a valid result and
    // the mask covers 0..=63 with 33..=63 rejected. The old code took a
    // separate power-of-two branch here and could never return 32.
    #[test]
    fn power_of_two_bound_is_inclusive() {
        assert_eq!(10, TestBoundedRand::new([10]).next_bounded(32));
        assert_eq!(32, TestBoundedRand::new([32]).next_bounded(32));
        // 40 rejected (40 > 32); 8 accepted.
        assert_eq!(8, TestBoundedRand::new([40, 8]).next_bounded(32));
    }

    #[test]
    fn max_of_u32_max_needs_no_rejection() {
        assert_eq!(
            u32::MAX,
            TestBoundedRand::new([u32::MAX]).next_bounded(u32::MAX)
        );
        assert_eq!(0, TestBoundedRand::new([0]).next_bounded(u32::MAX));
    }
}
