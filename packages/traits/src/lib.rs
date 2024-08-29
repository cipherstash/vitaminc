use vitaminc_protected::{Paranoid, Zeroed};

pub trait OutputSize {
    const SIZE: usize;
}

/// Output size for Paranoid types with the same sized inner value.
impl<const N: usize, T> OutputSize for T
where
    T: Paranoid<Inner = [u8; N]>,
{
    const SIZE: usize = N;
}

pub trait FixedOutput<O>: Sized + OutputSize
where
    O: Sized,
{
    /// Consume value and write result into provided array.
    fn finalize_into(self, out: &mut O);

    /// Retrieve result and consume the hasher instance.
    #[inline]
    fn finalize_fixed(self) -> O
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        self.finalize_into(&mut out);
        out
    }
}

#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutput<O>: Sized + OutputSize
where
    // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
    O: Sized + Send,
{
    type Error;

    /// Consume value and write result into provided array.
    async fn try_finalize_into(self, out: &mut O) -> Result<(), Self::Error>;

    /// Retrieve result and consume the hasher instance.
    #[inline]
    async fn try_finalize_fixed(self) -> Result<O, Self::Error>
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        if let Err(err) = self.try_finalize_into(&mut out).await {
            Err(err)
        } else {
            Ok(out)
        }
    }
}

/// Trait for updating a hash with input data with a specific input type.
/// This differs from the `Update` trait in `digest` in that it takes a specific input type.
/// This allows us to reason about the input type and its sensitivity.
pub trait Update<T> {
    // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
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

pub trait FixedOutputReset<O>: OutputSize
where
    O: Paranoid,
{
    fn finalize_into_reset(&mut self, out: &mut O);

    fn finalize_reset(&mut self) -> O
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        self.finalize_into_reset(&mut out);
        out
    }
}

#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutputReset<O>: OutputSize
where
    O: Paranoid,
{
    type Error;

    async fn try_finalize_into_reset(&mut self, out: &mut O) -> Result<(), Self::Error>;

    #[inline]
    async fn try_finalize_fixed_reset(&mut self) -> Result<O, Self::Error>
    where
        O: Zeroed,
    {
        let mut out = Zeroed::zeroed();
        if let Err(err) = self.try_finalize_into_reset(&mut out).await {
            Err(err)
        } else {
            Ok(out)
        }
    }
}
