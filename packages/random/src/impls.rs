use crate::{Fill, Generatable, RandomError, SafeRand};
use std::num::NonZeroU16;
use vitaminc_protected::{Paranoid, Protected};
use zeroize::Zeroize;

impl Generatable for NonZeroU16 {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut buf: [u8; 2] = [0, 0];

        buf.try_fill(rng)
            .map_err(|_| RandomError::GenerationFailed)?;
        if let Some(value) = NonZeroU16::new(u16::from_be_bytes(buf)) {
            Ok(value)
        } else {
            // Because a 0 would be an invalid value we must try again (rejection sampling)
            Self::random(rng)
        }
    }
}

impl<const N: usize> Generatable for [u8; N] {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        // TODO: Consider using MaybeUninit
        let mut buf: [u8; N] = [0; N];

        buf.try_fill(rng)
            .map_err(|_| RandomError::GenerationFailed)?;

        Ok(buf)
    }
}

// TODO: Consider implementing for T: Generatable
impl Generatable for Protected<u16> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Protected::generate_ok(|| {
            let mut buf: [u8; 2] = [0, 0];

            if buf.try_fill(rng).is_ok() {
                Ok(u16::from_be_bytes(buf))
            } else {
                // Make sure we don't leak anything left-over
                buf.zeroize();
                Err(RandomError::GenerationFailed)
            }
        })
    }
}
