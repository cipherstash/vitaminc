// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub. See docs/documentation.md.
//! [AsyncFixedOutputReset]: crate::AsyncFixedOutputReset
//! [`AsyncFixedOutput`]: crate::AsyncFixedOutput
//!
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
use vitaminc_protected::Zeroed;
use vitaminc_traits::OutputSize;

/// Defines an asynchronous digest or MAC algorithm output function.
/// `N` is the output size in bytes.
/// `O` is the output type which must implement `OutputSize<N>`.
///
/// Implementations must fill the complete output on success and document
/// their error and cancellation behavior. This trait does not require the
/// returned futures to be `Send`.
///
/// # Examples
///
/// Adapt an already computed protected result to the consuming interface.
/// This example's future completes immediately, so it can be polled once
/// without an async runtime.
///
/// ```
/// use std::{future::Future, pin::pin, task::{Context, Poll, Waker}};
/// use vitaminc_async_traits::AsyncFixedOutput;
/// use vitaminc_protected::{Controlled, Protected};
/// struct PreparedOutput(Protected<[u8; 4]>);
/// impl AsyncFixedOutput<4, Protected<[u8; 4]>> for PreparedOutput {
///     type Error = std::convert::Infallible;
///     async fn try_finalize_into(self, out: &mut Protected<[u8; 4]>) -> Result<(), Self::Error> {
///         out.update(|bytes| bytes.copy_from_slice(self.0.risky_ref()));
///         Ok(())
///     }
/// }
/// let prepared = PreparedOutput(Protected::new([1, 2, 3, 4]));
/// let mut future = pin!(prepared.try_finalize_fixed());
/// let mut context = Context::from_waker(Waker::noop());
/// match future.as_mut().poll(&mut context) {
///     Poll::Ready(Ok(output)) => assert_eq!(output.risky_ref(), &[1, 2, 3, 4]),
///     _ => panic!("the example completes immediately"),
/// }
/// ```
#[allow(async_fn_in_trait)]
pub trait AsyncFixedOutput<const N: usize, O>: Sized
where
    // TODO: Make this bound on a "tagged" value (i.e. sensitive or safe)
    O: Sized + Send + OutputSize<N>,
{
    /// Failure to finalize, including remote-service failures for remote algorithms.
    type Error;

    /// Consume value and write result into provided array.
    ///
    /// # Errors and cancellation
    ///
    /// On success every output byte is initialized to the result. On error or
    /// cancellation, the algorithm is consumed and `out` may be partially
    /// modified unless the implementation promises otherwise. Discard or wipe
    /// that output before reuse. Dropping the future does not guarantee that a
    /// request already sent to a remote service is cancelled.
    async fn try_finalize_into(self, out: &mut O) -> Result<(), Self::Error>;

    /// Retrieve result and consume the hasher instance.
    ///
    /// Starts with [`Zeroed::zeroed`] output and returns it only on success.
    /// Errors from [`try_finalize_into`](Self::try_finalize_into) are forwarded.
    /// On error or cancellation the temporary is dropped; wiping depends on
    /// `O`'s drop implementation, since `Zeroed` alone does not promise it.
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
    /// Failure to finalize or reset the algorithm.
    type Error;

    /// Write the complete result and reset to the initial message state on success.
    ///
    /// The algorithm's configuration, such as its key, is retained for reuse.
    ///
    /// # Errors and cancellation
    ///
    /// No generic rollback guarantee is made for either `self` or `out` on
    /// error or cancellation. Implementations must document whether the input
    /// survives and whether retrying is valid. Without a stronger guarantee,
    /// discard the output and recreate the algorithm before retrying. Dropping
    /// a future does not necessarily cancel a remote operation.
    async fn try_finalize_into_reset(&mut self, out: &mut O) -> Result<(), Self::Error>;

    /// Finalize into a zero-initialized temporary, returning it only on success.
    ///
    /// Forwards errors and reset semantics from
    /// [`try_finalize_into_reset`](Self::try_finalize_into_reset). On error or
    /// cancellation the temporary is dropped according to `O`'s drop behavior;
    /// the algorithm's state may already have changed.
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
