//! Resolve the path the generated code uses to reach `vitaminc-protected`.
//!
//! Callers reach the protected crate in different ways: as a direct
//! dependency (possibly renamed in their `Cargo.toml`), through the `vitaminc`
//! umbrella crate as `vitaminc::protected`, or from inside `vitaminc-protected`
//! itself. No single hard-coded path works for all of them, so the derives
//! look the dependency up in the invoking package's manifest, and accept a
//! `crate = "..."` override for layouts the lookup cannot see (for example a
//! re-export through some other crate).

use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use syn::{parse_quote, Ident, Path};

/// The root path of the protected crate for one derive invocation.
///
/// `override_path` is the value of the derive's `crate = "..."` attribute and
/// wins when present. Otherwise, in order:
///
/// 1. `vitaminc-protected` as a dependency gives `::<its name>`, and the crate
///    itself gives `::vitaminc_protected` (it declares
///    `extern crate self as vitaminc_protected;`, and its own tests and doc
///    tests reach it by that name).
/// 2. `vitaminc` as a dependency gives `::<its name>::protected`.
///
/// `attr` names the derive's attribute (`opaque_debug` or `timing_safe`) for
/// the error when neither crate is found.
pub fn protected_crate_path(override_path: Option<Path>, attr: &str) -> syn::Result<Path> {
    if let Some(path) = override_path {
        return Ok(path);
    }

    match crate_name("vitaminc-protected") {
        Ok(FoundCrate::Itself) => return Ok(parse_quote!(::vitaminc_protected)),
        Ok(FoundCrate::Name(name)) => {
            let name = Ident::new(&name, Span::call_site());
            return Ok(parse_quote!(::#name));
        }
        Err(_) => {}
    }

    match crate_name("vitaminc") {
        Ok(FoundCrate::Itself) => Ok(parse_quote!(crate::protected)),
        Ok(FoundCrate::Name(name)) => {
            let name = Ident::new(&name, Span::call_site());
            Ok(parse_quote!(::#name::protected))
        }
        Err(_) => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "this derive needs a dependency on `vitaminc-protected`, or on `vitaminc` \
                 with the `protected` feature; otherwise name the crate with \
                 `#[{attr}(crate = \"path::to::protected\")]`"
            ),
        )),
    }
}

/// Parse the value of a `crate = "..."` attribute key as a path.
pub fn parse_crate_value(meta: &syn::meta::ParseNestedMeta<'_>) -> syn::Result<Path> {
    let lit: syn::LitStr = meta.value()?.parse()?;
    lit.parse().map_err(|_| {
        syn::Error::new(
            lit.span(),
            "`crate` must be a path to the protected crate, such as `crate = \"vitaminc::protected\"`",
        )
    })
}
