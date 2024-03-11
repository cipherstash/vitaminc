use zeroize::Zeroize;
use crate::{Paranoid, Protected};
// TODO: Feature flag
use generic_array::{ArrayLength, GenericArray};

impl<T: Zeroize> From<T> for Protected<T> {
    fn from(x: T) -> Self {
        Self(x)
    }
}

impl<const N: usize> From<[char; N]> for Protected<String> {
    fn from(x: [char; N]) -> Self {
        Self(x.iter().collect())
    }
}

impl<const N: usize, U> From<GenericArray<u8, U>> for Protected<[u8; N]>
where
    U: ArrayLength,
    [u8; N]: From<GenericArray<u8, U>>,
{
    fn from(x: GenericArray<u8, U>) -> Self {
        Self::new(x.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_protected_u8() {
        let x: u8 = 42;
        let y: Protected<u8> = x.into();
        assert_eq!(y.0, 42);
    }

    #[test]
    fn test_into_protected_array_u8() {
        let x: [u8; 32] = [42; 32];
        let y: Protected<[u8; 32]> = x.into();
        assert_eq!(y.0, [42; 32]);
    }

    #[test]
    fn test_char_array_into_string() {
        let x: [char; 10] = ['c', 'o', 'o', 'k', 'i', 'e', 's', '!', '!', '!'];
        let y: Protected<String> = x.into();
        assert_eq!(y.0, "cookies!!!");
    }

    #[test]
    fn test_from_generic_array() {
        let x: GenericArray<u8, generic_array::typenum::U3> = generic_array::arr![1, 2, 3];
        let y: Protected<[u8; 3]> = x.into();
        assert_eq!(y.0, [1, 2, 3]);
    }
}