#![deny(missing_docs)]
//! Derive field-by-field random generation for structs.
//!
//! Use [`Generatable`] through `vitaminc-random`, which re-exports both the
//! trait and this macro:
//!
//! ```sh
//! cargo add vitaminc-random
//! ```
//!
//! # Compatibility
//!
//! Requires Rust <!-- msrv:vitaminc-random-derives -->**1.88.0**<!-- /msrv -->. This procedural macro runs on the compiler host;
//! the parent crate requires `std`. This crate has no Cargo feature flags.
//! MSRV increases require a minor release; patch releases retain the existing
//! floor. See the [workspace policy](https://github.com/cipherstash/vitaminc#compatibility).
//!
//! License: MIT.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Implement `Generatable` by generating each field from the supplied RNG.
///
/// Supports named, tuple, and unit structs without generic parameters. Every
/// field must implement `Generatable`; fields are generated in declaration
/// order, and the first error is returned. A unit struct consumes no randomness.
/// Enums and unions are rejected. There are no helper attributes.
///
/// Import `vitaminc_random::Generatable` into scope. Generated code also names
/// `vitaminc_random::SafeRand` and `vitaminc_random::RandomError` directly, so
/// depend on `vitaminc-random` under its original name. A facade-only dependency
/// or a renamed dependency is not sufficient. Generic structs need a manual
/// implementation: the macro does not carry generic parameters into the impl.
///
/// The derive does not wrap or wipe its fields. For secret values, use field
/// types that protect their contents.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU16;
/// use vitaminc_random::{Generatable, SafeRand, SeedableRng};
///
/// #[derive(Generatable)]
/// struct Draw {
///     value: NonZeroU16,
/// }
///
/// // A fixed seed makes this public test example reproducible.
/// let mut rng = SafeRand::seed_from_u64(7);
/// let draw = Draw::random(&mut rng)?;
/// assert!(draw.value.get() > 0);
/// # Ok::<(), vitaminc_random::RandomError>(())
/// ```
#[proc_macro_derive(Generatable)]
pub fn derive_generatable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let result_expr = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => {
                let field_inits = fields_named.named.iter().map(|f| {
                    let field_name = f.ident.as_ref().unwrap();
                    quote! {
                        #field_name: Generatable::random(rng)?
                    }
                });
                quote! {
                    Ok(Self {
                        #(#field_inits),*
                    })
                }
            }
            Fields::Unnamed(fields_unnamed) => {
                let field_inits = fields_unnamed.unnamed.iter().map(|_| {
                    quote! {
                        Generatable::random(rng)?
                    }
                });
                quote! {
                    Ok(Self(
                        #(#field_inits),*
                    ))
                }
            }
            Fields::Unit => {
                quote! { Ok(Self) }
            }
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                name,
                "#[derive(Generatable)] is not supported for enums — implement Generatable manually for cryptographic safety."
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                name,
                "#[derive(Generatable)] cannot be used on unions.",
            )
            .to_compile_error()
            .into();
        }
    };

    let expanded = quote! {
        impl Generatable for #name {
            fn random(rng: &mut vitaminc_random::SafeRand) -> Result<Self, vitaminc_random::RandomError> {
                #result_expr
            }
        };
    };

    TokenStream::from(expanded)
}
