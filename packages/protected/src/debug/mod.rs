use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// Opaque `Debug` for secret-bearing types.
///
/// This module provides the [`OpaqueDebug`] marker trait and a `#[derive(OpaqueDebug)]`
/// macro that **also** implements [`core::fmt::Debug`] for your type in a way that
/// **never** reveals internal data.
///
/// By default, the generated `Debug` implementation prints a placeholder that includes
/// the type’s fully-qualified name via [`core::any::type_name`]:
///
/// You can override this placeholder with an attribute on the type.
///
/// ## Why use this?
///
/// - Prevents accidental leakage of secrets (keys, tokens, passwords) via `Debug`
///   in logs or error messages.
/// - Keeps a meaningful breadcrumb (the type name) for diagnostics without exposing data.
/// - Allows the usage of [`Debug`] on outer types without risk.
///
/// ## What it generates
///
/// `#[derive(OpaqueDebug)]` generates:
///
/// 1. An impl of the marker trait:
///    ```ignore
///    impl OpaqueDebug for YourType {}
///    ```
/// 2. An impl of `core::fmt::Debug` that **never** formats internal fields.
///
/// ## Usage
///
/// ### Basic: default placeholder uses the fully-qualified type name
///
/// ```rust
/// use vitaminc_protected::OpaqueDebug;
///
/// #[derive(OpaqueDebug)]
/// struct ApiToken([u8; 32]);
///
/// let t = ApiToken([0; 32]);
/// let out = format!("{t:?}");
/// assert!(out.contains("ApiToken(\"***\")"));
/// ```
///
/// ### Works with generics
///
/// The `Debug` impl includes the instantiated type parameters in the placeholder.
///
/// ```rust
/// use vitaminc_protected::OpaqueDebug;
///
/// #[derive(OpaqueDebug)]
/// struct Key<const N: usize>([u8; N]);
///
/// let env = Key::<32>([0u8; 32]);
/// let out = format!("{env:?}");
/// assert!(out.contains("Key<32>(\"***\")"));
/// ```
///
/// ### Enums and unit-like types are supported
///
/// The internal representation is still hidden.
///
/// ```rust
/// use vitaminc_protected::OpaqueDebug;
///
/// #[derive(OpaqueDebug)]
/// enum SecretThing {
///     A(u32),
///     B { x: u8, y: u8 },
///     C,
/// }
///
/// let s = SecretThing::B { x: 7, y: 9 };
/// let out = format!("{s:?}");
/// assert!(out.contains("SecretThing::B {x: \"***\", y: \"***\"}"));
/// ```
///
/// ### Marking non-sensitive fields
///
/// You can mark individual fields as non-sensitive using the `#[non_sensitive]` attribute.
/// This is useful when you actually want to include certain fields in the debug output.
///
/// ```rust
/// use vitaminc_protected::OpaqueDebug;
///
/// #[derive(OpaqueDebug)]
/// struct HasNonSensitiveField {
///     sensitive: String,
///     #[non_sensitive]
///     value: String,
/// }
///
/// let out = format!(
///     "{:?}",
///     HasNonSensitiveField {
///         sensitive: "do-not-print".into(),
///         value: "ok-to-print".into(),
///     }
/// );
/// assert!(out.contains("HasNonSensitiveField { sensitive: \"***\", value: \"ok-to-print\" }"));
/// ```
///
/// ### Using with Redacted wrapper (optional)
///
/// This is useful to manage external types.
///
/// ```rust
/// use core::fmt;
/// use vitaminc_protected::{OpaqueDebug, Redacted};
///
/// let safe = Redacted::new([0u8; 32]);
/// assert_eq!(format!("{:?}", safe), "Redacted<[u8; 32] ***>");
/// ```
///
/// See also [`Redacted`].
///
/// ## Notes
///
/// - The derive intentionally **replaces** any `Debug` you might otherwise derive or write.
/// - The default placeholder is computed with `core::any::type_name::<T>()` at runtime.
/// - The marker trait has no methods; it exists to make trait bounds and wrapper impls
///   straightforward (e.g., a wrapper can `impl<T: OpaqueDebug> Debug for Redacted<T>`).
///
/// ### Feature compatibility
///
/// This module works in `no_std` environments; it only depends on `core`.
///
/// Happy redacting 👋
pub trait OpaqueDebug {}

/// Wrapper type for redacting debug output which implements [`OpaqueDebug`] for all types.
///
/// # Example
///
/// ```
/// use vitaminc_protected::Redacted;
///
/// let redacted = Redacted::new([0u8; 32]);
/// assert_eq!(format!("{:?}", redacted), "Redacted<[u8; 32] ***>");
/// ```
///
#[repr(transparent)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Create a new `Redacted` instance.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume the `Redacted` instance and return the inner value.
    /// CAUTION: this will remove the opaque redaction if the inner type implements `Debug`.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Redacted<T> {
    /// Get a reference to the inner value.
    /// CAUTION: this will remove the opaque redaction if the inner type implements `Debug`.
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> core::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Redacted<{} ***>", std::any::type_name::<T>())
    }
}

impl<T> OpaqueDebug for Redacted<T> {}

impl<T> Zeroize for Redacted<T>
where
    T: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T> Clone for Redacted<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Redacted(self.0.clone())
    }
}

impl<T> Serialize for Redacted<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("Redacted")
    }
}

impl<'de, T> Deserialize<'de> for Redacted<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let x = T::deserialize(deserializer)?;
        Ok(Redacted(x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redacted_debug() {
        let redacted = Redacted(42);
        assert_eq!(format!("{redacted:?}"), "Redacted<i32 ***>");
    }
}
