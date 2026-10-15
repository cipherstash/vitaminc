use std::collections::BTreeSet;

use crate::crate_path::{parse_crate_value, protected_crate_path};
use crate::hygiene::Locals;
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenTree};
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    ext::IdentExt, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput, Field,
    Fields, Type,
};

// Hygiene: the generated impls carry the input's generics and sit in the
// caller's module, so every name they introduce or call must be one the input
// cannot capture.
//
// - The formatter is `__opaque_debug_f`, and enum fields are bound as
//   `__f_<name>` or `__fN`, so a field or a lowercase const parameter named
//   `f` cannot collide with them.
// - Const parameters and items in the caller's scope must not capture the
//   formatter parameter or the field bindings. `crate::hygiene::Locals` names
//   them clear of every identifier in the input and emits dummy `fn`s that
//   shadow such items: the formatter's in the `const _: () = { ... };` block
//   around the impls, the field bindings' at the top of `fmt`. See that
//   module for what each placement can and cannot capture.
// - Macros and `core` items are called by absolute path (`::core::write!`,
//   `::core::fmt::Debug`), so a same-named macro at the call site does not
//   take their place.
// - The `OpaqueDebug` marker trait is named through the protected crate's
//   path, resolved per invocation by `crate_path::protected_crate_path`, so
//   the derive works without a `use` whether the caller depends on
//   `vitaminc-protected` (under any name) or on the `vitaminc` umbrella.
pub fn derive_opaque_debug(input: DeriveInput) -> TokenStream {
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let OpaqueDebugAttrs { mask, krate } = parse_attrs(input)?;
    let krate = protected_crate_path(krate, "opaque_debug")?;

    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let marker_impl = quote! {
        #[automatically_derived]
        impl #impl_generics #krate::OpaqueDebug for #ident #ty_generics #where_clause {}
    };

    // The `Debug` impl needs `FieldTy: Debug` for each field it formats
    // (`#[non_sensitive]`) whose type mentions a type parameter. Masked fields
    // are never formatted, so a fully masked generic type keeps working with a
    // non-`Debug` argument. The bounds go on the `Debug` impl only.
    let mut debug_generics = input.generics.clone();
    let type_params: BTreeSet<String> = input
        .generics
        .type_params()
        .map(|p| p.ident.to_string())
        .collect();
    {
        let where_clause = debug_generics.make_where_clause();
        for ty in shown_field_types(&input.data, &type_params) {
            where_clause
                .predicates
                .push(syn::parse_quote!(#ty: ::core::fmt::Debug));
        }
    }
    let (debug_impl_generics, _, debug_where_clause) = debug_generics.split_for_impl();

    let mut locals = Locals::new(input);
    let formatter = locals.param("__opaque_debug_f", Span::call_site());

    let body = match &input.data {
        Data::Struct(ds) => debug_body_for_struct(ds, &mask, &formatter),
        Data::Enum(de) => debug_body_for_enum(de, &mask, &formatter, &mut locals),
        // For unions: just print the type name
        Data::Union(_) => quote! {
            #formatter.write_str(::core::any::type_name::<Self>())
        },
    };

    let param_shadows = locals.param_shadows();
    let body_shadows = locals.body_shadows();

    Ok(quote! {
        const _: () = {
            #param_shadows

            #marker_impl

            #[automatically_derived]
            impl #debug_impl_generics ::core::fmt::Debug
                for #ident #ty_generics #debug_where_clause
            {
                fn fmt(
                    &self,
                    #formatter: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    #body_shadows
                    #body
                }
            }
        };
    })
}

fn has_non_sensitive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("non_sensitive"))
}

/// The field name as `Debug` should print it: `r#type` prints as `type`.
fn field_key(field: &Field) -> String {
    field.ident.as_ref().unwrap().unraw().to_string()
}

/// Whether `ty` names any of `type_params` anywhere in its tokens.
///
/// This is a token-level over-approximation (`other::T` also matches `T`),
/// which at worst adds a `Debug` bound the field needs anyway.
fn mentions_type_param(ty: &Type, type_params: &BTreeSet<String>) -> bool {
    fn walk(tokens: proc_macro2::TokenStream, type_params: &BTreeSet<String>) -> bool {
        tokens.into_iter().any(|tt| match tt {
            TokenTree::Ident(id) => type_params.contains(&id.to_string()),
            TokenTree::Group(g) => walk(g.stream(), type_params),
            _ => false,
        })
    }
    !type_params.is_empty() && walk(ty.to_token_stream(), type_params)
}

/// Types of the fields the `Debug` impl formats rather than masks, limited to
/// those that mention a type parameter, de-duplicated by token string.
fn shown_field_types(data: &Data, type_params: &BTreeSet<String>) -> Vec<Type> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |field: &Field, shown: bool| {
        if shown
            && mentions_type_param(&field.ty, type_params)
            && seen.insert(field.ty.to_token_stream().to_string())
        {
            out.push(field.ty.clone());
        }
    };

    match data {
        Data::Struct(ds) => {
            for field in &ds.fields {
                push(field, has_non_sensitive(&field.attrs));
            }
        }
        Data::Enum(de) => {
            for v in &de.variants {
                let variant_ns = has_non_sensitive(&v.attrs);
                for field in &v.fields {
                    push(field, variant_ns || has_non_sensitive(&field.attrs));
                }
            }
        }
        Data::Union(_) => {}
    }
    out
}

struct OpaqueDebugAttrs {
    /// The placeholder for masked fields (default `***`).
    mask: String,
    /// The `crate = "..."` override for the protected crate's path.
    krate: Option<syn::Path>,
}

/// Parse `#[opaque_debug(mask = "...", crate = "...")]` using syn v2
/// `parse_nested_meta`.
fn parse_attrs(input: &DeriveInput) -> syn::Result<OpaqueDebugAttrs> {
    let mut attrs = OpaqueDebugAttrs {
        mask: "***".to_string(),
        krate: None,
    };

    for attr in &input.attrs {
        if !attr.path().is_ident("opaque_debug") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("mask") {
                let lit: syn::LitStr = meta.value()?.parse()?;
                attrs.mask = lit.value();
                return Ok(());
            }
            if meta.path.is_ident("crate") {
                attrs.krate = Some(parse_crate_value(&meta)?);
                return Ok(());
            }
            // Unknown keys produce a nice error tied to the attribute span
            Err(meta.error("unsupported attribute; expected `mask = \"...\"` or `crate = \"...\"`"))
        })?;
    }

    Ok(attrs)
}

fn debug_body_for_struct(
    ds: &DataStruct,
    mask: &str,
    formatter: &syn::Ident,
) -> proc_macro2::TokenStream {
    match &ds.fields {
        Fields::Named(named) => {
            // Use DebugStruct and decide per-field based on #[non_sensitive]
            let fields = named.named.iter().map(|f| {
                let fname = f.ident.as_ref().unwrap();
                let key = field_key(f);
                if has_non_sensitive(&f.attrs) {
                    // show actual value
                    quote_spanned! { f.span() => .field(#key, &self.#fname) }
                } else {
                    // mask
                    quote_spanned! { f.span() => .field(#key, &#mask) }
                }
            });

            quote! {
                #formatter
                    .debug_struct(::core::any::type_name::<Self>())
                    #(#fields)*
                    .finish()
            }
        }
        Fields::Unnamed(unnamed) => {
            // Use DebugTuple and decide per-field based on #[non_sensitive]
            let fields = unnamed.unnamed.iter().enumerate().map(|(i, f)| {
                let idx = syn::Index::from(i);
                if has_non_sensitive(&f.attrs) {
                    quote_spanned! { f.span() => .field(&self.#idx) }
                } else {
                    quote_spanned! { f.span() => .field(&#mask) }
                }
            });

            quote! {
                #formatter
                    .debug_tuple(::core::any::type_name::<Self>())
                    #(#fields)*
                    .finish()
            }
        }
        Fields::Unit => quote! {
            #formatter.write_str(::core::any::type_name::<Self>())
        },
    }
}

/// Each arm prints `path::Enum::` and then formats the variant through
/// `debug_struct`/`debug_tuple`, so enum output matches struct output
/// (`path::E::V { a: "***" }`) and honours `{:#?}`.
fn debug_body_for_enum(
    de: &DataEnum,
    mask: &str,
    formatter: &syn::Ident,
    locals: &mut Locals,
) -> proc_macro2::TokenStream {
    let arms = de.variants.iter().map(|v| {
        let v_ident = &v.ident;
        let variant_ns = has_non_sensitive(&v.attrs);
        let prefix = quote! {
            ::core::write!(
                #formatter,
                "{}::",
                ::core::any::type_name::<Self>(),
            )?;
        };

        match &v.fields {
            Fields::Unit => quote! {
                Self::#v_ident => {
                    #prefix
                    #formatter.write_str(::core::stringify!(#v_ident))
                }
            },

            Fields::Unnamed(fields) => {
                // bind each field by ref
                let mut arm = locals.scope();
                let bind_ids: Vec<syn::Ident> = (0..fields.unnamed.len())
                    .map(|i| arm.bind(&format!("__f{i}"), v.span()))
                    .collect();

                let writes = fields.unnamed.iter().zip(&bind_ids).map(|(f, local)| {
                    if variant_ns || has_non_sensitive(&f.attrs) {
                        quote_spanned! { f.span() => .field(#local) }
                    } else {
                        quote_spanned! { f.span() => .field(&#mask) }
                    }
                });

                quote! {
                    Self::#v_ident( #( ref #bind_ids ),* ) => {
                        #prefix
                        #formatter
                            .debug_tuple(::core::stringify!(#v_ident))
                            #(#writes)*
                            .finish()
                    }
                }
            }

            Fields::Named(fields) => {
                // Bind each field to a prefixed local rather than its own name,
                // as the tuple arm does with `__f0`, `__f1`, ... so a field
                // cannot shadow the generated locals.
                let mut arm = locals.scope();
                let bindings: Vec<(&syn::Ident, syn::Ident)> = fields
                    .named
                    .iter()
                    .map(|field| {
                        let id = field.ident.as_ref().unwrap();
                        (id, arm.bind(&format!("__f_{}", id.unraw()), id.span()))
                    })
                    .collect();

                let pat_bindings = bindings.iter().map(|(id, local)| quote!(#id: ref #local));

                let writes = fields.named.iter().zip(&bindings).map(|(f, (_, local))| {
                    let key = field_key(f);
                    if variant_ns || has_non_sensitive(&f.attrs) {
                        quote_spanned! { f.span() => .field(#key, #local) }
                    } else {
                        quote_spanned! { f.span() => .field(#key, &#mask) }
                    }
                });

                quote! {
                    Self::#v_ident { #( #pat_bindings ),* } => {
                        #prefix
                        #formatter
                            .debug_struct(::core::stringify!(#v_ident))
                            #(#writes)*
                            .finish()
                    }
                }
            }
        }
    });

    // `*self` rather than `self`, so an empty enum's `match {}` is exhaustive.
    // Every binding is `ref`, so nothing is moved out.
    quote! {
        match *self {
            #(#arms)*
        }
    }
}
