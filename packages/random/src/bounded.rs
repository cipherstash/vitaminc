use crate::SafeRand;
use rand::CryptoRng;
use vitaminc_protected::{Controlled, Protected};

/// A trait for generating random numbers within a specific range.
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

fn next_bounded_u32<R: CryptoRng>(rng: &mut R, max: u32) -> u32 {
    if max.is_power_of_two() {
        rng.next_u32() & (max - 1)
    } else {
        let cap = max.next_power_of_two();
        // Use rejection sampling to avoid modulo bias
        let mut value = rng.next_u32() % cap;
        while value > max {
            value = rng.next_u32() % cap;
        }
        value
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use rand::TryCryptoRng;

    use super::{next_bounded_u32, BoundedRng};

    struct TestBoundedRand(u32);
    impl rand::TryRng for TestBoundedRand {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.0 as u64)
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

    #[test]
    fn test_next_non_power2_less_than_cap() {
        let mut rng = TestBoundedRand(8);
        assert_eq!(8, rng.next_bounded(10));
    }

    #[test]
    fn test_next_non_power2_more_than_cap() {
        let mut rng = TestBoundedRand(25);
        assert_eq!(9, rng.next_bounded(10));
    }

    #[test]
    fn test_next_power2_less_than_cap() {
        let mut rng = TestBoundedRand(10);
        assert_eq!(10, rng.next_bounded(32));
    }

    #[test]
    fn test_next_power2_more_than_cap() {
        let mut rng = TestBoundedRand(40);
        assert_eq!(8, rng.next_bounded(32));
    }
}
