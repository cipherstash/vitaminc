use async_trait::async_trait;
use vitaminc_protected::{AsProtectedRef, Paranoid};

pub trait FixedOutput: Sized {
    type Output: Paranoid;

    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut Self::Output);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> Self::Output
    where
        <Self as FixedOutput>::Output: Default,
    {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }
}

pub trait Update<T: Paranoid> {
    fn update<'a, A>(&mut self, data: &'a A)
    where
        A: ?Sized + AsProtectedRef<'a, [u8]>;

    /// Digest input data in a chained manner.
    #[must_use]
    fn chain<'a, A>(mut self, data: &'a A) -> Self
    where
        A: AsProtectedRef<'a, [u8]>,
        Self: Sized,
    {
        self.update(data);
        self
    }
}

#[async_trait]
pub trait AsyncMac {
    type Output: Paranoid;
    type Error;

    async fn finalize_async(self) -> Result<Self::Output, Self::Error>;
}
