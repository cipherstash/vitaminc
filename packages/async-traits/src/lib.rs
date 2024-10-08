#![doc = include_str!("../README.md")]
use vitaminc_protected::Zeroed;
use vitaminc_traits::OutputSize;

/// Defines an asynchronous digest or MAC algorithm output function.
/// `N` is the output size in bytes.
/// `O` is the output type which must implement `OutputSize<N>`.
#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutput<const N: usize, O>: Sized
where
    // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
    O: Sized + Send + OutputSize<N>,
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

/// Defines an asynchronous digest or MAC algorithm output function that resets the state.
/// `N` is the output size in bytes.
/// `O` is the output type which must implement `OutputSize<N>`.
#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutputReset<const N: usize, O>
where
    O: OutputSize<N>,
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
