#![deny(missing_docs)]
//! Derives for redacted debug output and timing-safe field comparisons.
//!
//! Use these macros through `vitaminc-protected`, which re-exports them with
//! their traits. Install the parent crate with:
//!
//! ```sh
//! cargo add vitaminc-protected
//! ```
//!
//! They also work through `vitaminc::protected` with the facade's `protected`
//! feature. Renamed dependencies are detected. If the traits are re-exported
//! elsewhere, use `#[opaque_debug(crate = "path::to::protected")]` and
//! `#[timing_safe(crate = "path::to::protected")]` on the type.
//!
//! [`OpaqueDebug`] hides field values unless explicitly marked public.
//! [`TimingSafeEq`] generates the comparison trait and `PartialEq`/`Eq`.
//! Neither macro wipes memory; use protected wrappers for that.
//!
//! # Compatibility
//!
//! Requires Rust <!-- msrv:vitaminc-protected-derive -->**1.88.0**<!-- /msrv -->. These procedural macros run on the compiler host;
//! the parent crate requires `std`. This crate has no Cargo feature flags.
//! MSRV increases require a minor release; patch releases retain the existing
//! floor. See the [workspace policy](https://github.com/cipherstash/vitaminc#compatibility).
//!
//! License: MIT.

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod crate_path;
mod hygiene;
mod opaque_debug;
mod timing_safe;

/// Derive redacted `Debug` and the `OpaqueDebug` marker trait.
///
/// Supports named, tuple, and unit structs, enums, and generics. Union output
/// contains only the type name. Struct and enum output reveals type, variant,
/// and field names; this macro hides values, not the shape of the type.
///
/// # Attributes
///
/// - On the type, `#[opaque_debug(mask = "...")]` replaces the default `***`.
/// - On the type, `#[opaque_debug(crate = "...")]` overrides the trait path.
/// - On a field, `#[non_sensitive]` prints its value using `Debug`.
/// - On an enum variant, `#[non_sensitive]` prints all that variant's fields.
///
/// Only expose fields safe to put in logs. Displayed fields need `Debug`;
/// masked fields do not. Do not also derive or implement `Debug` on the type.
///
/// # Examples
///
/// ```
/// use vitaminc_protected::OpaqueDebug;
///
/// #[derive(OpaqueDebug)]
/// #[opaque_debug(mask = "redacted")]
/// struct Token {
///     #[non_sensitive]
///     version: u8,
///     secret: [u8; 32],
/// }
///
/// let token = Token { version: 1, secret: [7; 32] };
/// let text = format!("{token:?}");
/// assert!(text.contains("version: 1"));
/// assert!(text.contains("redacted"));
/// assert!(!text.contains("[7,"));
/// ```
#[proc_macro_derive(OpaqueDebug, attributes(opaque_debug, non_sensitive))]
pub fn derive_opaque_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    opaque_debug::derive_opaque_debug(input)
}

/// Derive `TimingSafeEq`, `PartialEq`, and `Eq` using field comparisons.
///
/// Supports named, tuple, and unit structs, enums, and generics. Every field
/// must implement `TimingSafeEq`. Comparisons combine field results without
/// short-circuiting; their timing properties still depend on the field impls.
/// Enum comparisons branch on the variants, so the variant must not be secret.
/// Variable-length fields may expose their lengths.
///
/// Unions are accepted but always compare unequal, including to themselves;
/// this does not satisfy `Eq`'s reflexivity contract. Do not use this derive
/// on unions. Unit structs always compare equal.
///
/// The only helper option is the type-level `#[timing_safe(crate = "...")]`
/// path override. Do not also derive or implement `PartialEq` or `Eq`.
///
/// # Examples
///
/// ```
/// use vitaminc_protected::TimingSafeEq;
///
/// #[derive(TimingSafeEq)]
/// struct Tag([u8; 32]);
///
/// let tag = Tag([7; 32]);
/// assert!(bool::from(tag.ts_eq(&Tag([7; 32]))));
/// assert!(!bool::from(tag.ts_eq(&Tag([8; 32]))));
/// ```
#[proc_macro_derive(TimingSafeEq, attributes(timing_safe))]
pub fn derive_timing_safe(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    timing_safe::derive_timing_safe(input)
}
