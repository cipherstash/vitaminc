use paranoid::{Paranoid, Protected};
use random::{Generatable, RandomError, SafeRand};

const STANDARD_CHARS: [char; 94] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'e', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'x',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '~', '`', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '+', '=', '{', '[', '}', ']', '|', '\\', ':', ';', '"', '\'', '<', ',', '>', '.', '?', '/',
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
    fn generate(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_bounded_u32(STANDARD_CHARS.len() as u32);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Password::new(password))
    }
}

impl<const N: usize> Generatable for AlphaNumericPassword<N> {
    fn generate(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_bounded_u32(62);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Self(Password::new(password)))
    }
}

impl<const N: usize> Generatable for AlphaPassword<N> {
    fn generate(rng: &mut SafeRand) -> Result<Self, RandomError> {
        let mut password: [char; N] = [0x00 as char; N];
        (0..N).for_each(|i| {
            let char = rng.next_bounded_u32(52);
            password[i] = STANDARD_CHARS[char as usize];
        });
        Ok(Self(Password::new(password)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{AlphaNumericPassword, AlphaPassword};

    use super::Password;
    use random::{Generatable, SafeRand, SeedableRng};

    #[test]
    fn test_generate_password() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy();
        let value: Password<16> = Generatable::generate(&mut rng)?;
        dbg!(value.into_unprotected_string());

        assert!(false);
        Ok(())
    }

    #[test]
    fn test_generate_alphanumeric_password() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy();
        let value: AlphaNumericPassword<16> = Generatable::generate(&mut rng)?;
        dbg!(value.into_unprotected_string());

        assert!(false);
        Ok(())
    }

    #[test]
    fn test_generate_alpha_password() -> Result<(), crate::RandomError> {
        let mut rng = SafeRand::from_entropy();
        let value: AlphaPassword<16> = Generatable::generate(&mut rng)?;
        dbg!(value.into_unprotected_string());

        assert!(false);
        Ok(())
    }
}


