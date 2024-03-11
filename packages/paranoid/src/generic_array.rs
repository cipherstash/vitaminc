use generic_array::{ArrayLength, GenericArray};
use crate::Paranoid;

impl<const N: usize, U> From<GenericArray<u8, U>> for Paranoid<[u8; N]>
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
    use generic_array::arr;
    use crate::Paranoid;

    #[test]
    fn test_generic_array_to_paranoid() {
        assert_eq!(Paranoid::<[u8; 3]>::from(arr![1, 2, 3]), Paranoid::new([1, 2, 3]));
        let x: Paranoid<[u8; 5]> = arr![1, 2, 3, 4, 5].into();
        assert_eq!(x, Paranoid::new([1, 2, 3, 4, 5]));
    }
}