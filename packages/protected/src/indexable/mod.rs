use crate::private::ParanoidPrivate;
use std::ops::Index;

pub struct Indexable<T>(pub(crate) T);

impl<T> Indexable<T> {
    /// Create a new `Indexable` from an inner value.
    pub fn new(x: <Indexable<T> as ParanoidPrivate>::Inner) -> Self
    where
        Self: ParanoidPrivate,
    {
        Self::init_from_inner(x)
    }
}

impl<T> Index<usize> for Indexable<T>
where
    T: ParanoidPrivate,
    <T as ParanoidPrivate>::Inner: Index<usize>,
{
    type Output = <<T as ParanoidPrivate>::Inner as Index<usize>>::Output; // TODO: Wrap this in a Protected

    fn index(&self, index: usize) -> &Self::Output {
        &self.inner()[index]
    }
}

// TODO: Canwe make a blanket impl for all Paranoid types?
impl<T: ParanoidPrivate> ParanoidPrivate for Indexable<T> {
    type Inner = T::Inner;

    fn init_from_inner(x: Self::Inner) -> Self {
        Self(T::init_from_inner(x))
    }

    fn inner(&self) -> &Self::Inner {
        self.0.inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protected;

    #[test]
    fn indexable() {
        let x: Indexable<Protected<[u8; 4]>> = Indexable::new([1, 2, 3, 4]);
        assert_eq!(x[0], 1);
    }
}