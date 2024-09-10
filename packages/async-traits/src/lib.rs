#![doc = include_str!("../README.md")]
use vitaminc_protected::{Controlled, Zeroed};
use vitaminc_traits::OutputSize;

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

#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutputReset<O>: OutputSize
where
    O: Controlled,
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
