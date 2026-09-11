use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// Number of letters at the front of [`STANDARD_CHARS`]: `A..=Z` then
/// `a..=z`. [`AlphaPassword`] draws from `STANDARD_CHARS[..ALPHA_LEN]`.
const ALPHA_LEN: usize = 52;
/// Number of letters and digits at the front of [`STANDARD_CHARS`]: the
/// letters, then `0..=9`. [`AlphaNumericPassword`] draws from
/// `STANDARD_CHARS[..ALPHANUMERIC_LEN]`. The ordering both constants depend
/// on is pinned by `standard_chars_are_distinct_and_ordered_by_class`.
const ALPHANUMERIC_LEN: usize = 62;

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

/// `N` characters drawn independently from `set`, each with one fixed-count
/// draw in `0..set.len()`, so the index is always in bounds and every
/// character of the set is reachable. Each draw is uniform to within the
/// `set.len() / 2⁶⁴` bias bound documented on
/// [`BoundedRng`](vitaminc_random::BoundedRng); for the sets in this crate
/// the exact statistical distance from uniform is at most 2⁻⁶⁰ per
/// character.
fn fill<const N: usize>(rng: &mut SafeRand, set: &[char]) -> [char; N] {
    let mut password: [char; N] = [0x00 as char; N];
    for slot in password.iter_mut() {
        *slot = set[rng.next_below(set.len() as u32) as usize];
    }
    password
}

impl<const N: usize> Generatable for Password<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Ok(Password::new(fill(rng, &STANDARD_CHARS)))
    }
}

impl<const N: usize> Generatable for AlphaNumericPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Ok(Self(Password::new(fill(
            rng,
            &STANDARD_CHARS[..ALPHANUMERIC_LEN],
        ))))
    }
}

impl<const N: usize> Generatable for AlphaPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Ok(Self(Password::new(fill(rng, &STANDARD_CHARS[..ALPHA_LEN]))))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AlphaNumericPassword, AlphaPassword, ALPHANUMERIC_LEN, ALPHA_LEN, STANDARD_CHARS};

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
        assert!(STANDARD_CHARS[..ALPHA_LEN]
            .iter()
            .all(|c| c.is_ascii_alphabetic()));
        assert!(STANDARD_CHARS[ALPHA_LEN..ALPHANUMERIC_LEN]
            .iter()
            .all(|c| c.is_ascii_digit()));
        assert!(STANDARD_CHARS[ALPHANUMERIC_LEN..]
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

    /// Every character of each narrow set is drawn, and nothing outside it:
    /// the position lookup is into the *whole* table, so a character past
    /// the narrow set's end indexes past the tally array and panics. A
    /// membership-only check would still pass if a set's bound shrank by
    /// one (dropping `'9'` or `'z'`); the tally catches that too.
    #[test]
    fn narrow_sets_reach_their_last_character() {
        let mut rng = SafeRand::from_seed(SEED);
        let mut alnum = [false; ALPHANUMERIC_LEN];
        let mut alpha = [false; ALPHA_LEN];
        for _ in 0..SAMPLES {
            let value: AlphaNumericPassword<16> = Generatable::random(&mut rng).expect("random");
            for c in chars(value.0) {
                alnum[STANDARD_CHARS.iter().position(|&s| s == c).expect("in set")] = true;
            }
            let value: AlphaPassword<16> = Generatable::random(&mut rng).expect("random");
            for c in chars(value.0) {
                alpha[STANDARD_CHARS.iter().position(|&s| s == c).expect("in set")] = true;
            }
        }
        assert!(
            alnum.iter().all(|&s| s),
            "alphanumeric set not fully reachable"
        );
        assert!(alpha.iter().all(|&s| s), "alpha set not fully reachable");
    }
}
