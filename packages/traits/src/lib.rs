use async_trait::async_trait;
use vitaminc_protected::Paranoid;

pub trait OutputSize {
    const SIZE: usize;
}

/// Output size for Paranoid types with the same sized inner value.
impl<const N: usize, T> OutputSize for T where T: Paranoid<Inner = [u8; N]> {
    const SIZE: usize = N;
}

pub trait FixedOutput<O>: Sized + OutputSize where O: Sized {
    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut O);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> O
    where
        O: Default,
    {
        let mut out = Default::default();
        self.finalize_into(&mut out);
        out
    }
}

/// Trait for updating a hash with input data with a specific input type.
/// This differs from the `Update` trait in `digest` in that it takes a specific input type.
/// This allows us to reason about the input type and its sensitivity.
pub trait Update<T> { // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
    fn update(&mut self, data: T);

    /// Digest input data in a chained manner.
    #[must_use]
    fn chain(mut self, data: T) -> Self
    where
        Self: Sized,
    {
        self.update(data);
        self
    }
}

// TODO: Replace this with trait-variant
#[async_trait]
pub trait AsyncMac<O>: OutputSize where O: Paranoid {
    type Error;

    async fn finalize_async(self) -> Result<O, Self::Error>;
}

#[async_trait]
pub trait AsyncFixedOutputReset<O>: OutputSize where O: Paranoid {
    type Error;

    async fn finalize_reset(&mut self) -> Result<O, Self::Error>;
}