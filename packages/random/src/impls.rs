use std::num::NonZeroU16;
use crate::{Generatable, RandomError, SafeRand};
use rand::Fill;


impl Generatable for NonZeroU16 {
    fn generate(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut buf: [u8; 2] = [0, 0];

        buf.try_fill(rng).map_err(|_| RandomError::GenerationFailed)?;
        if let Some(value) = NonZeroU16::new(u16::from_be_bytes(buf)) {
            Ok(value)
        } else {
            // Because a 0 would be an invalid value we must try again (rejection sampling)
            Self::generate(rng)
        }
    }
}