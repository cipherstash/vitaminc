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

/// Trait for updating a hash with input data with a specific input type.
/// This differs from the `Update` trait in `digest` in that it takes a specific input type.
/// This allows us to reason about the input type and its sensitivity.
pub trait Update<T>
where
    T: for<'a> AsProtectedRef<'a, [u8]>,
{
    fn update(&mut self, data: &T);

    /// Digest input data in a chained manner.
    #[must_use]
    fn chain(mut self, data: &T) -> Self
    where
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
