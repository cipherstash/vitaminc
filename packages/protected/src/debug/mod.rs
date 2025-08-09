//! Opaque `Debug` for secret-bearing types.
//!
//! This module provides the [`OpaqueDebug`] marker trait and a `#[derive(OpaqueDebug)]`
//! macro that **also** implements [`core::fmt::Debug`] for your type in a way that
//! **never** reveals internal data.
//!
//! By default, the generated `Debug` implementation prints a placeholder that includes
//! the type’s fully-qualified name via [`core::any::type_name`]:
//!
//! ```text
//! Secret<your_crate::module::Type>
//! ```
//!
//! You can override this placeholder with an attribute on the type.
//!
//! ## Why use this?
//!
//! - Prevents accidental leakage of secrets (keys, tokens, passwords) via `Debug`
//!   in logs or error messages.
//! - Keeps a meaningful breadcrumb (the type name) for diagnostics without exposing data.
//! - Plays nicely with other wrappers (e.g., a [`crate::Protected<T>`] that zeroizes on drop).
//!
//! ## What it generates
//!
//! `#[derive(OpaqueDebug)]` generates:
//!
//! 1. An impl of the marker trait:
//!    ```ignore
//!    impl OpaqueDebug for YourType {}
//!    ```
//! 2. An impl of `core::fmt::Debug` that **never** formats internal fields.
//!
//! ## Usage
//!
//! ### Basic: default placeholder uses the fully-qualified type name
//!
//! ```rust
//! use vitaminc_protected::OpaqueDebug;
//!
//! #[derive(OpaqueDebug)]
//! struct ApiToken([u8; 32]);
//!
//! let t = ApiToken([0; 32]);
//! let out = format!("{t:?}");
//! assert!(out.contains("ApiToken (***)"));
//! ```
//!
//! ### Works with generics
//!
//! The `Debug` impl includes the instantiated type parameters in the placeholder.
//!
//! ```rust
//! use vitaminc_protected::OpaqueDebug;
//!
//! #[derive(OpaqueDebug)]
//! struct Key<const N: usize>([u8; N]);
//!
//! let env = Key::<32>([0u8; 32]);
//! let out = format!("{env:?}");
//! assert!(out.contains("Key<32> (***)"));
//! ```
//!
//! ### Enums and unit-like types are supported
//!
//! The internal representation is still hidden.
//!
//! ```rust
//! use vitaminc_protected::OpaqueDebug;
//!
//! #[derive(OpaqueDebug)]
//! enum SecretThing {
//!     A(u32),
//!     B { x: u8, y: u8 },
//!     C,
//! }
//!
//! let s = SecretThing::B { x: 7, y: 9 };
//! let out = format!("{s:?}");
//! assert!(out.contains("SecretThing::B { x: ***, y: *** }"));
//! ```
//!
//! ### Using with Redacted wrapper (optional)
//!
//! This is useful to manage external types.
//!
//! ```rust
//! use core::fmt;
//! use vitaminc_protected::{OpaqueDebug, Redacted};
//!
//! let safe = Redacted::new([0u8; 32]);
//! assert_eq!(format!("{:?}", safe), "Redacted<[u8; 32] ***>");
//! ```
//!
//! ## Notes
//!
//! - The derive intentionally **replaces** any `Debug` you might otherwise derive or write.
//! - The default placeholder is computed with `core::any::type_name::<T>()` at runtime.
//! - The marker trait has no methods; it exists to make trait bounds and wrapper impls
//!   straightforward (e.g., a wrapper can `impl<T: OpaqueDebug> Debug for Redacted<T>`).
//!
//! ### Feature compatibility
//!
//! This module works in `no_std` environments; it only depends on `core`.
//!
//! ---
//!
//! Happy redacting 👋

pub use protected_derive::OpaqueDebug;

/// Marker trait implemented by `#[derive(OpaqueDebug)]`.
/// See [the module level documentation](self) for more.
pub trait OpaqueDebug {}

/// Wrapper type for redacting debug output.
/// See [the module level documentation](self) for more.
#[repr(transparent)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Create a new `Redacted` instance.
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> core::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Redacted<{} ***>", std::any::type_name::<T>())
    }
}

impl<T> OpaqueDebug for Redacted<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_debug() {
        let redacted = Redacted(42);
        assert_eq!(format!("{:?}", redacted), "Redacted<i32 ***>");
    }
}
