//! The one place holding the key-provider traits' native/wasm32 `Send`
//! and `Sync` split.
//!
//! [`KeyProvider`](super::KeyProvider) and
//! [`IndexKeyProvider`](super::IndexKeyProvider) return futures that
//! consumers such as Stack Encrypt drive on multi-threaded runtimes, so on
//! native targets those futures must be `Send`. On wasm32 the host-backed
//! transport futures are not `Send` and the runtimes are single-threaded, so
//! the bound would only get in the way. [`MaybeSend`] lets each trait be
//! written once for both targets instead of as a `#[cfg]` pair.
//!
//! [`MaybeSync`] is the same split for `Sync`. A wrapper provider such as
//! [`FixedIndexKeySource`](super::FixedIndexKeySource) borrows its inner
//! provider across an `.await`, so on native targets its future is `Send`
//! only if the inner provider is `Sync`. On wasm32 nothing needs `Sync`, so
//! a wrapper bounds its inner provider by [`MaybeSync`] and accepts a
//! provider that is not `Sync` there (for example, one that holds a
//! `RefCell`).
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

/// Alias for `Sync` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually. The blanket impl covers everything the
/// target allows.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

/// Alias for `Sync` on native targets; satisfied by every type on wasm32.
///
/// Never implement this manually. The blanket impl covers everything the
/// target allows.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}
