// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [`Password`]: crate::Password
//! [`AlphaNumericPassword`]: crate::AlphaNumericPassword
//! [`AlphaPassword`]: crate::AlphaPassword
//!
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]

use vitaminc_protected::{Controlled, OpaqueDebug};
use vitaminc_random::{Generatable, SafeRand};

#[doc(no_inline)]
pub use vitaminc_protected::Protected;
#[doc(no_inline)]
pub use vitaminc_random::RandomError;

#[cfg(test)]
mod cleanup_tests;

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

/// A generated password of `N` non-space printable ASCII characters.
///
/// Use [`Password::generate`] for the default 20 characters, or
/// [`Generatable::random`] with a securely seeded [`SafeRand`] for a longer
/// password. Building a generation call with `N < 20` fails compilation.
/// The 94-character alphabet gives approximately 131 bits at the minimum
/// length. Character selection uses [`SafeRand::next_below`]'s near-uniform
/// bounded draw; see [Randomness and entropy](crate#randomness-and-entropy)
/// for the bias bound and seed requirements.
///
/// The characters are wiped on drop, and `Debug` reveals no contents. There
/// is no raw-value constructor, ordinary equality, or implicit string access.
///
/// # Examples
///
/// ```
/// use vitaminc_password::Password;
/// let password: Password<20> = Password::generate()?;
/// let secret = password.into_protected_string();
/// # Ok::<(), vitaminc_password::RandomError>(())
/// ```
#[derive(OpaqueDebug)]
pub struct Password<const N: usize>(Protected<[char; N]>);

/// A generated password of `N` ASCII letters and digits (`A-Z`, `a-z`, `0-9`).
///
/// [`AlphaNumericPassword::generate`] produces 22 characters, approximately
/// 131 bits. Building a [`Generatable::random`] call with `N < 22` fails
/// compilation. Choosing this alphabet does not guarantee a digit or a
/// letter of each case. Contents are wiped on drop and redacted in `Debug`.
///
/// # Examples
///
/// ```
/// use vitaminc_password::AlphaNumericPassword;
/// let password: AlphaNumericPassword<22> = AlphaNumericPassword::generate()?;
/// let secret = password.into_protected_string();
/// # Ok::<(), vitaminc_password::RandomError>(())
/// ```
#[derive(OpaqueDebug)]
pub struct AlphaNumericPassword<const N: usize>(Password<N>);

/// A generated password of `N` ASCII letters (`A-Z`, `a-z`).
///
/// [`AlphaPassword::generate`] produces 23 characters, approximately 131 bits.
/// Building a [`Generatable::random`] call with `N < 23` fails compilation.
/// Choosing this alphabet does not guarantee both cases. Contents are wiped
/// on drop and redacted in `Debug`.
///
/// # Examples
///
/// ```
/// use vitaminc_password::AlphaPassword;
/// let password: AlphaPassword<23> = AlphaPassword::generate()?;
/// let secret = password.into_protected_string();
/// # Ok::<(), vitaminc_password::RandomError>(())
/// ```
#[derive(OpaqueDebug)]
pub struct AlphaPassword<const N: usize>(Password<N>);

impl Password<20> {
    /// Generate 20 characters using fresh operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError::SeedingFailed`] if the OS cannot supply entropy.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::Password::generate()?;
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn generate() -> Result<Self, RandomError> {
        Self::random(&mut SafeRand::from_entropy()?)
    }
}

impl AlphaNumericPassword<22> {
    /// Generate 22 letters/digits using fresh operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError::SeedingFailed`] if the OS cannot supply entropy.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaNumericPassword::generate()?;
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn generate() -> Result<Self, RandomError> {
        Self::random(&mut SafeRand::from_entropy()?)
    }
}

impl AlphaPassword<23> {
    /// Generate 23 letters using fresh operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError::SeedingFailed`] if the OS cannot supply entropy.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaPassword::generate()?;
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn generate() -> Result<Self, RandomError> {
        Self::random(&mut SafeRand::from_entropy()?)
    }
}

impl<const N: usize> Password<N> {
    /// The number of ASCII characters (and encoded bytes), without exposing them.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::Password::generate()?;
    /// assert_eq!(password.len(), 20);
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the password is empty. Generated passwords are always nonempty.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::Password::generate()?;
    /// assert!(!password.is_empty());
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    const VALID_LENGTH: () = assert!(N >= 20, "Password requires at least 20 characters");

    /// Consume the password, wiping its source array, and export a plain string.
    ///
    /// The returned string is **not** automatically wiped. Prefer
    /// [`Self::into_protected_string`] and borrow at the external boundary.
    /// Use this only when that interface requires ownership of a `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// let exported = vitaminc_password::Password::generate()?.into_unprotected_string();
    /// assert_eq!(exported.len(), 20);
    /// // The owner of `exported` is now responsible for its cleanup.
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_unprotected_string(self) -> String {
        self.into_protected_string().risky_unwrap()
    }

    /// Consume the password and return a string that is wiped on drop.
    ///
    /// The source array stays protected until it is dropped and wiped. The
    /// destination is protected before characters are copied, including during
    /// unwinding, and is allocated once with room for all `N` ASCII bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::Password::generate()?;
    /// assert_eq!(password.len(), 20);
    /// let secret = password.into_protected_string();
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_protected_string(self) -> Protected<String> {
        // Only the generators construct Password: every char is ASCII. Keeping
        // the source wrapped (rather than using Controlled::map) ensures its
        // drop still wipes it. Protect the destination before writing secrets.
        protected_string(self.0.risky_ref().iter().copied())
    }
}

impl<const N: usize> AlphaNumericPassword<N> {
    /// The number of ASCII characters (and encoded bytes), without exposing them.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaNumericPassword::generate()?;
    /// assert_eq!(password.len(), 22);
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the password is empty. Generated passwords are always nonempty.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaNumericPassword::generate()?;
    /// assert!(!password.is_empty());
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    const VALID_LENGTH: () = assert!(
        N >= 22,
        "AlphaNumericPassword requires at least 22 characters"
    );

    /// Export a plain string, transferring cleanup responsibility to its owner.
    /// Prefer [`Self::into_protected_string`]. See [`Password::into_unprotected_string`].
    ///
    /// # Examples
    ///
    /// ```
    /// let exported = vitaminc_password::AlphaNumericPassword::generate()?.into_unprotected_string();
    /// assert_eq!(exported.len(), 22);
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_unprotected_string(self) -> String {
        self.0.into_unprotected_string()
    }

    /// Convert to a string that is wiped on drop, wiping the source array.
    /// See [`Password::into_protected_string`] for allocation and cleanup behavior.
    ///
    /// # Examples
    ///
    /// ```
    /// let secret = vitaminc_password::AlphaNumericPassword::generate()?.into_protected_string();
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_protected_string(self) -> Protected<String> {
        self.0.into_protected_string()
    }
}

impl<const N: usize> AlphaPassword<N> {
    /// The number of ASCII characters (and encoded bytes), without exposing them.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaPassword::generate()?;
    /// assert_eq!(password.len(), 23);
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the password is empty. Generated passwords are always nonempty.
    ///
    /// # Examples
    ///
    /// ```
    /// let password = vitaminc_password::AlphaPassword::generate()?;
    /// assert!(!password.is_empty());
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    const VALID_LENGTH: () = assert!(N >= 23, "AlphaPassword requires at least 23 characters");

    /// Export a plain string, transferring cleanup responsibility to its owner.
    /// Prefer [`Self::into_protected_string`]. See [`Password::into_unprotected_string`].
    ///
    /// # Examples
    ///
    /// ```
    /// let exported = vitaminc_password::AlphaPassword::generate()?.into_unprotected_string();
    /// assert_eq!(exported.len(), 23);
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_unprotected_string(self) -> String {
        self.0.into_unprotected_string()
    }

    /// Convert to a string that is wiped on drop, wiping the source array.
    /// See [`Password::into_protected_string`] for allocation and cleanup behavior.
    ///
    /// # Examples
    ///
    /// ```
    /// let secret = vitaminc_password::AlphaPassword::generate()?.into_protected_string();
    /// # Ok::<(), vitaminc_password::RandomError>(())
    /// ```
    pub fn into_protected_string(self) -> Protected<String> {
        self.0.into_protected_string()
    }
}

// Callers supply exactly the generated ASCII characters, so the iterator's
// length is the required byte capacity. Keep this helper private: arbitrary
// Unicode input could outgrow that allocation. Iterating explicitly also lets
// the cleanup test inject an unwind after a known number of bytes are written.
fn protected_string(chars: impl ExactSizeIterator<Item = char>) -> Protected<String> {
    let mut output = Protected::new(String::with_capacity(chars.len()));
    for c in chars {
        output.update(|string| string.push(c));
    }
    output
}

/// `N` characters drawn independently from `set`, each with one fixed-count
/// draw in `0..set.len()`, so the index is always in bounds and every
/// character of the set is reachable. Each draw is uniform to within the
/// `set.len() / 2⁶⁴` bias bound documented on
/// [`BoundedRng`](vitaminc_random::BoundedRng); for the sets in this crate
/// the exact statistical distance from uniform is at most 2⁻⁵⁹ per
/// character.
fn draw_chars<const N: usize>(rng: &mut SafeRand, set: &[char]) -> Protected<[char; N]> {
    let mut password = Protected::new(['\0'; N]);
    for slot in password.risky_inner_mut().iter_mut() {
        *slot = set[rng.next_below(set.len() as u32) as usize];
    }
    password
}

impl<const N: usize> Generatable for Password<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let () = Self::VALID_LENGTH;
        Ok(Self(draw_chars(rng, &STANDARD_CHARS)))
    }
}

impl<const N: usize> Generatable for AlphaNumericPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let () = Self::VALID_LENGTH;
        Ok(Self(Password(draw_chars(
            rng,
            &STANDARD_CHARS[..ALPHANUMERIC_LEN],
        ))))
    }
}

impl<const N: usize> Generatable for AlphaPassword<N> {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let () = Self::VALID_LENGTH;
        Ok(Self(Password(draw_chars(
            rng,
            &STANDARD_CHARS[..ALPHA_LEN],
        ))))
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

    #[test]
    fn defaults_have_the_promised_types_lengths_and_alphabets() -> Result<(), crate::RandomError> {
        let standard: Password<20> = Password::generate()?;
        let alnum: AlphaNumericPassword<22> = AlphaNumericPassword::generate()?;
        let alpha: AlphaPassword<23> = AlphaPassword::generate()?;
        for (value, length, alphabet) in [
            (standard.into_protected_string(), 20, &STANDARD_CHARS[..]),
            (
                alnum.into_protected_string(),
                22,
                &STANDARD_CHARS[..ALPHANUMERIC_LEN],
            ),
            (
                alpha.into_protected_string(),
                23,
                &STANDARD_CHARS[..ALPHA_LEN],
            ),
        ] {
            assert_eq!(value.risky_ref().len(), length);
            assert!(value.risky_ref().chars().all(|c| alphabet.contains(&c)));
        }
        Ok(())
    }

    #[test]
    fn minimum_lengths_are_the_shortest_to_exceed_128_bits() {
        for (length, alphabet) in [(20, 94_u32), (22, 62), (23, 52)] {
            let bits_per_character = f64::from(alphabet).log2();
            assert!(f64::from(length) * bits_per_character > 128.0);
            assert!(f64::from(length - 1) * bits_per_character < 128.0);
        }
    }

    #[test]
    fn conversions_preserve_every_character_and_debug_is_opaque() {
        // Fixed seeds are fixtures only. Compare each public conversion with
        // the generated array, not just with the other conversion: two equally
        // broken exports must not make the test pass.
        macro_rules! check {
            ($ty:ident, $n:literal, $inner:expr) => {{
                let mut rng = SafeRand::from_seed(SEED);
                let value = $ty::<$n>::random(&mut rng).unwrap();
                assert_eq!(value.len(), $n);
                assert!(!value.is_empty());
                let inner: fn(&$ty<$n>) -> &Protected<[char; $n]> = $inner;
                let source = inner(&value);
                let expected: String = source.risky_ref().iter().collect();
                let debug = format!("{value:?}");
                assert!(!debug.contains(&expected));
                assert!(debug.contains("***"));
                let protected = value.into_protected_string();
                assert_eq!(protected.risky_ref(), &expected);
                assert_eq!(protected.risky_ref().len(), $n);
                let mut rng = SafeRand::from_seed(SEED);
                let exported = $ty::<$n>::random(&mut rng)
                    .unwrap()
                    .into_unprotected_string();
                assert_eq!(exported, expected);
            }};
        }
        use vitaminc_protected::Protected;
        check!(Password, 20, |Password(chars)| chars);
        check!(AlphaNumericPassword, 22, |AlphaNumericPassword(
            Password(chars),
        )| chars);
        check!(AlphaPassword, 23, |AlphaPassword(Password(chars))| chars);
        check!(Password, 128, |Password(chars)| chars);
        check!(AlphaNumericPassword, 128, |AlphaNumericPassword(
            Password(chars),
        )| chars);
        check!(AlphaPassword, 128, |AlphaPassword(Password(chars))| chars);
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
            let value: Password<20> = Generatable::random(&mut rng).expect("random");
            for c in value.into_protected_string().risky_ref().chars() {
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
    /// the narrow set's end is caught by the check on its index. A
    /// membership-only check would still pass if a set's bound shrank by
    /// one (dropping `'9'` or `'z'`); the tally catches that too.
    #[test]
    fn narrow_sets_reach_their_last_character() {
        let mut rng = SafeRand::from_seed(SEED);
        let mut alnum = [false; ALPHANUMERIC_LEN];
        let mut alpha = [false; ALPHA_LEN];
        for _ in 0..SAMPLES {
            let value: AlphaNumericPassword<22> = Generatable::random(&mut rng).expect("random");
            for c in value.into_protected_string().risky_ref().chars() {
                let idx = STANDARD_CHARS.iter().position(|&s| s == c).expect("in set");
                assert!(
                    idx < ALPHANUMERIC_LEN,
                    "alphanumeric password drew {c:?}, which is outside its set"
                );
                alnum[idx] = true;
            }
            let value: AlphaPassword<23> = Generatable::random(&mut rng).expect("random");
            for c in value.into_protected_string().risky_ref().chars() {
                let idx = STANDARD_CHARS.iter().position(|&s| s == c).expect("in set");
                assert!(
                    idx < ALPHA_LEN,
                    "alpha password drew {c:?}, which is outside its set"
                );
                alpha[idx] = true;
            }
        }
        assert!(
            alnum.iter().all(|&s| s),
            "alphanumeric set not fully reachable"
        );
        assert!(alpha.iter().all(|&s| s), "alpha set not fully reachable");
    }
}
