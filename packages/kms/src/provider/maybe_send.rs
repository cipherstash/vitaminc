//! The one place holding the key-provider traits' native/wasm32 `Send`
//! split.
//!
//! [`KeyProvider`](super::KeyProvider) and
//! [`IndexKeyProvider`](super::IndexKeyProvider) return futures that
//! consumers such as Stack Encrypt drive on multi-threaded runtimes, so on
//! native targets those futures must be `Send`. On wasm32 the host-backed
//! transport futures are not `Send` and the runtimes are single-threaded, so
//! the bound would only get in the way. [`MaybeSend`] lets each trait be
//! written once for both targets instead of as a `#[cfg]` pair.
//!
//! The capability traits ([`GenerateDataKey`](crate::GenerateDataKey) and
//! friends) deliberately carry no such bound: they are plain `async fn`
//! (CIP-3986), which is why every data key source gets a concrete,
//! non-generic provider impl rather than one blanket impl.

/// Alias for `Send` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually. The blanket impl covers everything the
/// target allows.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// Alias for `Send` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually. The blanket impl covers everything the
/// target allows.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}
