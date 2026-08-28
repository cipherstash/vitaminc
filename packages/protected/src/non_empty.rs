//! Non-empty context values. This module is private; its documentation lives
//! on [`IsEmpty`] (what "empty" means) and [`NonEmpty`] (why, and the two
//! ways to build one).

use std::borrow::Cow;

/// Structural emptiness of a value, decided **before** any encoding is applied.
///
/// A value is empty when it carries no caller-supplied bytes:
///
/// | value | empty when |
/// |---|---|
/// | `()` | always |
/// | `str`, `String`, `[u8]`, `[u8; N]`, `Vec<u8>`, `Cow<[u8]>` | `len() == 0` |
/// | integers | never — a number is caller information |
/// | `Option<T>` | `None`, or `Some(t)` with `t` empty |
/// | `(A, B)` | **both** components empty |
/// | [`NonEmpty<T>`] | never, by construction |
///
/// A composite is empty only when it contributes nothing: `("", "email")`
/// still separates from `("", "id")`, so it is not empty, whereas `("", "")`,
/// `Some("")` and `Some(None)` are. This is the definition a downstream crate
/// would otherwise have to reconstruct by parsing the encoded bytes.
///
/// Because the check runs before encoding, an *already-encoded* context (a
/// `PrfContext` or `Aad` built from an empty value) is judged on its encoded
/// bytes, which are usually non-empty because of framing. The check is for
/// values handed to vitaminc, not for values vitaminc has already framed.
///
/// Implement this for your own context types so they can be wrapped in
/// [`NonEmpty`].
pub trait IsEmpty {
    /// Returns `true` if this value carries no caller-supplied bytes.
    fn is_empty(&self) -> bool;
}

impl IsEmpty for () {
    fn is_empty(&self) -> bool {
        true
    }
}

impl IsEmpty for str {
    fn is_empty(&self) -> bool {
        str::is_empty(self)
    }
}

impl IsEmpty for String {
    fn is_empty(&self) -> bool {
        String::is_empty(self)
    }
}

impl IsEmpty for [u8] {
    fn is_empty(&self) -> bool {
        <[u8]>::is_empty(self)
    }
}

impl<const N: usize> IsEmpty for [u8; N] {
    fn is_empty(&self) -> bool {
        N == 0
    }
}

impl IsEmpty for Vec<u8> {
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

impl IsEmpty for Cow<'_, [u8]> {
    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

impl<T> IsEmpty for &T
where
    T: IsEmpty + ?Sized,
{
    fn is_empty(&self) -> bool {
        T::is_empty(self)
    }
}

macro_rules! never_empty {
    ($($ty:ty),+ $(,)?) => {$(
        /// An integer is caller information, so it is never empty.
        impl IsEmpty for $ty {
            fn is_empty(&self) -> bool {
                false
            }
        }
    )+};
}

never_empty!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// `None` is empty; `Some(value)` is as empty as `value`.
impl<T> IsEmpty for Option<T>
where
    T: IsEmpty,
{
    fn is_empty(&self) -> bool {
        match self {
            Some(value) => value.is_empty(),
            None => true,
        }
    }
}

/// A pair is empty only when **both** components are: a composite that still
/// contributes caller bytes on either side is not the degenerate case.
impl<A, B> IsEmpty for (A, B)
where
    A: IsEmpty,
    B: IsEmpty,
{
    fn is_empty(&self) -> bool {
        self.0.is_empty() && self.1.is_empty()
    }
}

/// The error returned when a value that must carry caller-supplied data
/// turned out to be [empty](IsEmpty).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("context value carries no caller-supplied data")]
pub struct EmptyError;

/// A context value proven to carry caller-supplied bytes.
///
/// An AEAD associated-data value and a PRF context can both legitimately be
/// empty. For some callers, though, an empty context is a security bug rather
/// than a degenerate case: when one value domain-separates every primitive a
/// field uses, an empty one collapses that separation — equal plaintexts in
/// different fields derive identical index terms, every field shares one
/// derived key, and ciphertexts become transplantable between fields.
///
/// `NonEmpty` lets such a caller *demand* non-emptiness in a bound, without
/// forcing the invariant on anyone who wants an empty context. It follows the
/// `NonZero` pattern: the check ([`IsEmpty`]) happens exactly once, at
/// construction, and after that the type carries the invariant, so an API can
/// take a `NonEmpty<C>` (or bound on [`TryIntoNonEmpty`]) instead of
/// re-checking on every use.
///
/// `NonEmpty<T>` is transparent to the vitaminc context traits: wrapping a
/// value changes nothing about how it is encoded, only what the type promises.
///
/// # Two ways to build one
///
/// Literals are checked at compile time with [`nonempty!`](crate::nonempty);
/// dynamic values are checked at runtime with [`NonEmpty::new`]. A plain
/// `&'static str` cannot be value-checked at compile time — `""` and
/// `"users/email"` are the same type — so an API that wants both a
/// compile-time guarantee for literals *and* a plain-string call site bounds
/// on [`TryIntoNonEmpty`], which accepts either form, and converts once on the
/// way in:
///
/// ```rust
/// use vitaminc_protected::{nonempty, EmptyError, NonEmpty, TryIntoNonEmpty};
///
/// fn bind<C: TryIntoNonEmpty>(context: C) -> Result<NonEmpty<C::Inner>, EmptyError> {
///     context.try_into_non_empty()
/// }
///
/// // A literal: proven non-empty at compile time, no runtime check.
/// assert!(bind(nonempty!("users/email")).is_ok());
///
/// // A plain string: checked structurally, once, here.
/// assert!(bind("users/email").is_ok());
/// assert_eq!(bind("").unwrap_err(), EmptyError);
///
/// // Nesting carries the invariant through.
/// assert!(bind(("users", Some("email"))).is_ok());
/// assert_eq!(bind(("", None::<&str>)).unwrap_err(), EmptyError);
/// ```
///
/// # Examples
///
/// ```rust
/// use vitaminc_protected::{nonempty, EmptyError, NonEmpty};
///
/// // Runtime-checked, for dynamic values.
/// let field = String::from("users/email");
/// let context = NonEmpty::new(field)?;
/// assert_eq!(context.get(), "users/email");
///
/// assert_eq!(NonEmpty::new(String::new()).unwrap_err(), EmptyError);
///
/// // Compile-time-checked, for literals: `nonempty!("")` does not compile.
/// let context: NonEmpty<&'static str> = nonempty!("users/email");
/// assert_eq!(context.into_inner(), "users/email");
/// # Ok::<(), EmptyError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonEmpty<T>(T);

impl<T> NonEmpty<T>
where
    T: IsEmpty,
{
    /// Wraps `value`, checking once that it is not [empty](IsEmpty).
    ///
    /// # Errors
    ///
    /// Returns [`EmptyError`] if `value.is_empty()`.
    pub fn new(value: T) -> Result<Self, EmptyError> {
        if value.is_empty() {
            Err(EmptyError)
        } else {
            Ok(Self(value))
        }
    }
}

impl<T> NonEmpty<T> {
    /// Consumes the wrapper, returning the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Borrows the inner value.
    pub fn get(&self) -> &T {
        &self.0
    }
}

impl NonEmpty<&'static str> {
    /// Wraps a static string, checking at compile time when evaluated in a
    /// `const` context. Prefer [`nonempty!`](crate::nonempty), which does
    /// that for you.
    ///
    /// # Panics
    ///
    /// Panics if `value` is empty. In the initialiser of a `const` item that
    /// panic is a compile error, which is the point.
    /// At runtime it is a real panic, so use [`NonEmpty::new`] for values that
    /// are not literals.
    pub const fn from_static(value: &'static str) -> Self {
        assert!(!value.is_empty(), "a non-empty context cannot be empty");
        Self(value)
    }
}

/// Conversion into a [`NonEmpty`] that accepts either an already-proven
/// `NonEmpty<T>` (infallible, no check) or a raw value (checked structurally).
///
/// Bound on this to keep a plain-string call site while still rejecting an
/// empty context: `"users/email"` and [`nonempty!`](crate::nonempty)`("users/email")` both
/// satisfy it, and the literal form costs nothing at runtime.
///
/// # Examples
///
/// ```rust
/// use vitaminc_protected::{nonempty, EmptyError, TryIntoNonEmpty};
///
/// let checked = "users/email".try_into_non_empty()?;
/// let proven = nonempty!("users/email").try_into_non_empty()?;
/// assert_eq!(checked, proven);
///
/// assert_eq!("".try_into_non_empty().unwrap_err(), EmptyError);
/// # Ok::<(), EmptyError>(())
/// ```
pub trait TryIntoNonEmpty: Sized {
    /// The value carried by the resulting [`NonEmpty`].
    type Inner;

    /// Converts `self` into a [`NonEmpty`].
    ///
    /// # Errors
    ///
    /// Returns [`EmptyError`] if `self` is a raw value that is
    /// [empty](IsEmpty). A `NonEmpty` input never fails.
    fn try_into_non_empty(self) -> Result<NonEmpty<Self::Inner>, EmptyError>;
}

impl<T> TryIntoNonEmpty for T
where
    T: IsEmpty,
{
    type Inner = T;

    fn try_into_non_empty(self) -> Result<NonEmpty<T>, EmptyError> {
        NonEmpty::new(self)
    }
}

impl<T> TryIntoNonEmpty for NonEmpty<T> {
    type Inner = T;

    fn try_into_non_empty(self) -> Result<NonEmpty<T>, EmptyError> {
        Ok(self)
    }
}

/// A [`NonEmpty<&'static str>`](NonEmpty) checked at compile time.
///
/// Expands to a `const` item, so an empty literal fails to compile rather
/// than panicking at runtime. (A `const { … }` block would not do: its
/// evaluation is deferred to codegen, so `cargo check` — and any tool built
/// on it — would not report the error.)
///
/// ```rust
/// use vitaminc_protected::{nonempty, NonEmpty};
///
/// let context: NonEmpty<&'static str> = nonempty!("users/email");
/// assert_eq!(context.get(), &"users/email");
/// ```
///
/// ```rust,compile_fail
/// let context = vitaminc_protected::nonempty!("");
/// ```
#[macro_export]
macro_rules! nonempty {
    ($value:literal) => {{
        const CONTEXT: $crate::NonEmpty<&'static str> = $crate::NonEmpty::from_static($value);
        CONTEXT
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[test]
    fn empty_shapes_are_empty() {
        assert!(().is_empty_ctx());
        assert!("".is_empty_ctx());
        assert!(String::new().is_empty_ctx());
        assert!(b"".as_slice().is_empty_ctx());
        assert!([0u8; 0].is_empty_ctx());
        assert!(Vec::<u8>::new().is_empty_ctx());
        assert!(Cow::<[u8]>::Borrowed(&[]).is_empty_ctx());
        assert!(None::<&str>.is_empty_ctx());
        assert!(Some("").is_empty_ctx());
        assert!(("", "").is_empty_ctx());
        assert!(Some(None::<&str>).is_empty_ctx());
        assert!((None::<&str>, Some("")).is_empty_ctx());
        assert!(((), ()).is_empty_ctx());
    }

    #[test]
    fn shapes_carrying_information_are_not_empty() {
        assert!(!"users/email".is_empty_ctx());
        assert!(!"x".is_empty_ctx());
        assert!(!String::from("x").is_empty_ctx());
        assert!(!b"raw".as_slice().is_empty_ctx());
        assert!(![1u8].is_empty_ctx());
        assert!(!vec![1u8].is_empty_ctx());
        assert!(!Cow::<[u8]>::Owned(vec![1]).is_empty_ctx());
        assert!(!Some("users/email").is_empty_ctx());
        assert!(!("users", "email").is_empty_ctx());
        // A composite that still contributes bytes on one side is not the
        // degenerate case.
        assert!(!("", "email").is_empty_ctx());
        assert!(!("users", "").is_empty_ctx());
        assert!(!(None::<&str>, "email").is_empty_ctx());
        assert!(!Some(Some("x")).is_empty_ctx());
    }

    #[test]
    fn integers_are_never_empty() {
        assert!(!0u8.is_empty_ctx());
        assert!(!0u16.is_empty_ctx());
        assert!(!0u32.is_empty_ctx());
        assert!(!0u64.is_empty_ctx());
        assert!(!0u128.is_empty_ctx());
        assert!(!0i8.is_empty_ctx());
        assert!(!0i16.is_empty_ctx());
        assert!(!0i32.is_empty_ctx());
        assert!(!0i64.is_empty_ctx());
        assert!(!0i128.is_empty_ctx());
        assert!(!7u64.is_empty_ctx());
        assert!(!Some(0u64).is_empty_ctx());
    }

    #[test]
    fn references_defer_to_the_referent() {
        let owned = String::from("x");
        assert!(!<&String as IsEmpty>::is_empty(&&owned));
        assert!(!<&&String as IsEmpty>::is_empty(&&&owned));
        let empty = String::new();
        assert!(<&String as IsEmpty>::is_empty(&&empty));
        assert!(!<&[u8; 3] as IsEmpty>::is_empty(&b"abc"));
        assert!(!<&str as IsEmpty>::is_empty(&"abc"));
    }

    #[test]
    fn new_checks_once_at_construction() {
        assert_eq!(NonEmpty::new("").unwrap_err(), EmptyError);
        assert_eq!(NonEmpty::new(("", "")).unwrap_err(), EmptyError);
        assert_eq!(NonEmpty::new(None::<&str>).unwrap_err(), EmptyError);

        let context = NonEmpty::new("users/email").unwrap();
        assert_eq!(context.get(), &"users/email");
        assert_eq!(context.into_inner(), "users/email");

        let nested = NonEmpty::new(("users", Some("email"))).unwrap();
        assert_eq!(nested.into_inner(), ("users", Some("email")));
    }

    #[test]
    fn try_into_non_empty_accepts_both_forms() {
        let proven = nonempty!("users/email").try_into_non_empty().unwrap();
        let checked = "users/email".try_into_non_empty().unwrap();
        assert_eq!(proven, checked);

        assert_eq!("".try_into_non_empty().unwrap_err(), EmptyError);
        assert_eq!(String::new().try_into_non_empty().unwrap_err(), EmptyError);
        assert_eq!(
            (None::<&str>, "").try_into_non_empty().unwrap_err(),
            EmptyError
        );
        assert!(("", "email").try_into_non_empty().is_ok());
    }

    #[test]
    fn from_static_accepts_a_non_empty_literal() {
        const CONTEXT: NonEmpty<&'static str> = NonEmpty::from_static("users/email");
        assert_eq!(CONTEXT.get(), &"users/email");
        assert_eq!(nonempty!("users/email"), CONTEXT);
    }

    #[test]
    #[should_panic(expected = "a non-empty context cannot be empty")]
    fn from_static_panics_on_an_empty_string_at_runtime() {
        let empty = String::new();
        // Leak so the value is genuinely `'static` yet not a compile-time
        // constant; the `const fn` runs at runtime here.
        let leaked: &'static str = Box::leak(empty.into_boxed_str());
        let _ = NonEmpty::from_static(leaked);
    }

    #[test]
    fn error_is_displayable_and_stable() {
        assert_eq!(
            EmptyError.to_string(),
            "context value carries no caller-supplied data"
        );
    }

    #[quickcheck]
    fn new_succeeds_exactly_when_the_string_has_bytes(value: String) -> bool {
        NonEmpty::new(value.clone()).is_ok() != value.is_empty()
    }

    #[quickcheck]
    fn new_succeeds_exactly_when_the_bytes_are_non_empty(value: Vec<u8>) -> bool {
        NonEmpty::new(value.clone()).is_ok() != value.is_empty()
    }

    #[quickcheck]
    fn option_is_as_empty_as_its_payload(value: Option<String>) -> bool {
        let expected = value.as_ref().is_none_or(|inner| inner.is_empty());
        IsEmpty::is_empty(&value) == expected
    }

    #[quickcheck]
    fn pair_is_empty_only_when_both_sides_are(left: String, right: Vec<u8>) -> bool {
        let expected = left.is_empty() && right.is_empty();
        IsEmpty::is_empty(&(left, right)) == expected
    }

    /// Disambiguates from the inherent `is_empty` on `str`, `String`, `Vec`
    /// and slices so every assertion above exercises the trait.
    trait IsEmptyCtx {
        fn is_empty_ctx(&self) -> bool;
    }

    impl<T: IsEmpty + ?Sized> IsEmptyCtx for T {
        fn is_empty_ctx(&self) -> bool {
            IsEmpty::is_empty(self)
        }
    }
}
