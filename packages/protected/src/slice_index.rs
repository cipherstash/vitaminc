use crate::Protected;
use std::ops::Index;

/// Allows the use a of a Paranoid usize to index an array.
impl<const N: usize, T> Index<Protected<usize>> for [T; N] {
    type Output = T;

    fn index(&self, index: Protected<usize>) -> &Self::Output {
        &self[index.0]
    }
}
