use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand};

const STANDARD_CHARS: [char; 94] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-',
    '+', '=', '{', '[', '}', ']', '|', '\\', ':', ';', '"', '\'', '<', ',', '>', '.', '?', '/',
];

// TODO: Additional ideas
// To include a random string for additional "entropy"
// we could generate a random seed using SafeRand::from_entropy()
// then use an HKDF to generate a new seed from the random string along with user provided context
// and then use that as the seed for the password generation.

pub struct Password<const N: usize>(Protected<[char; N]>); // TODO: Use a Paranoid
pub struct AlphaNumericPassword<const N: usize>(Password<N>);
pub struct AlphaPassword<const N: usize>(Password<N>);

impl<const N: usize> Password<N> {
    // TODO: Use Into<Protected<String>>
    pub fn new(password: [char; N]) -> Self {
        Self(Protected::new(password))
    }
    /// Converts the password into a standard `String`.
    /// Once this happens, Zeroization is no longer guaranteed
    /// so only do this as a final step where the password is needed.
    pub fn into_unprotected_string(self) -> String {
        //self.0.iter().collect()
        unimplemented!()
    }

    pub fn into_protected_string(self) -> Protected<String> {
        unimplemented!("Paranoid string conversion")
    }
}

impl<const N: usize> AlphaNumericPassword<N> {
    /// Converts the password into a standard `String`.
    /// Once this happens, Zeroization is no longer guaranteed
    /// so only do this as a final step where the password is needed.
    pub fn into_unprotected_string(self) -> String {
        self.0.into_unprotected_string()
    }

    pub fn into_protected_string(self) -> Protected<String> {
        self.0.into_protected_string()
    }
}

impl<const N: usize> AlphaPassword<N> {
    /// Converts the password into a standard `String`.
    /// Once this happens, Zeroization is no longer guaranteed
    /// so only do this as a final step where the password is needed.
    pub fn into_unprotected_string(self) -> String {
        self.0.into_unprotected_string()
    }

    pub fn into_protected_string(self) -> Protected<String> {
        self.0.into_protected_string()
    }
}

impl<const N: usize> Generatable for Password<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_below(STANDARD_CHARS.len() as u32);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Password::new(password))
    }
}

impl<const N: usize> Generatable for AlphaNumericPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_below(62);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Self(Password::new(password)))
    }
}

impl<const N: usize> Generatable for AlphaPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_below(52);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Self(Password::new(password)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AlphaNumericPassword, AlphaPassword, STANDARD_CHARS};

    use super::Password;
    use vitaminc_protected::Controlled;
    use vitaminc_random::{Generatable, SafeRand, SeedableRng};

    const SEED: [u8; 32] = [7u8; 32];
    const SAMPLES: usize = 512;

    // `into_unprotected_string` is not implemented yet, so the tests read
    // the generated characters through the field, as crate-private code may.
    fn chars<const N: usize>(password: Password<N>) -> [char; N] {
        password.0.risky_unwrap()
    }

    #[test]
    fn standard_chars_are_distinct_and_ordered_by_class() {
        // Regression: the table once read `c, e, e, f`, no `d` and `e` at
        // double weight.
        let mut sorted = STANDARD_CHARS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), STANDARD_CHARS.len(), "duplicate character");
        assert!(STANDARD_CHARS[..52].iter().all(|c| c.is_ascii_alphabetic()));
        assert!(STANDARD_CHARS[52..62].iter().all(|c| c.is_ascii_digit()));
        assert!(STANDARD_CHARS[62..]
            .iter()
            .all(|c| c.is_ascii_punctuation()));
        assert!(STANDARD_CHARS.contains(&'d'));
    }

    #[test]
    fn generating_from_entropy_never_panics() -> Result<(), crate::RandomError> {
        // Regression for the out-of-bounds panic: the old inclusive draw
        // could return `STANDARD_CHARS.len()` itself (p ≈ 1/95 per
        // character). 200 × 64 characters makes that fail with overwhelming
        // probability.
        let mut rng = SafeRand::from_entropy()?;
        for _ in 0..200 {
            let _: Password<64> = Generatable::random(&mut rng)?;
            let _: AlphaNumericPassword<64> = Generatable::random(&mut rng)?;
            let _: AlphaPassword<64> = Generatable::random(&mut rng)?;
        }
        Ok(())
    }

    /// Every character of every password comes from its own set, and every
    /// character of the set turns up: the index is uniform in `0..len`,
    /// never `len` itself.
    #[test]
    fn passwords_draw_from_exactly_their_character_set() {
        let mut rng = SafeRand::from_seed(SEED);
        let mut seen = [false; 94];
        for _ in 0..SAMPLES {
            let value: Password<16> = Generatable::random(&mut rng).expect("random");
            for c in chars(value) {
                let idx = STANDARD_CHARS.iter().position(|&s| s == c).expect("in set");
                seen[idx] = true;
            }
        }
        assert!(
            seen.iter().all(|&s| s),
            "some standard character never drawn"
        );
    }

    #[test]
    fn alphanumeric_passwords_contain_only_alphanumerics() {
        let mut rng = SafeRand::from_seed(SEED);
        for _ in 0..SAMPLES {
            let value: AlphaNumericPassword<16> = Generatable::random(&mut rng).expect("random");
            let s = chars(value.0);
            assert!(s.iter().all(|c| c.is_ascii_alphanumeric()), "{s:?}");
        }
    }

    #[test]
    fn alpha_passwords_contain_only_letters() {
        let mut rng = SafeRand::from_seed(SEED);
        for _ in 0..SAMPLES {
            let value: AlphaPassword<16> = Generatable::random(&mut rng).expect("random");
            let s = chars(value.0);
            assert!(s.iter().all(|c| c.is_ascii_alphabetic()), "{s:?}");
        }
    }
}
