use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields, Path, Type};

use crate::crate_path::{parse_crate_value, protected_crate_path};
use crate::hygiene::{Locals, Scope};

// Hygiene: the impls carry the input's generics and expand in the caller's
// module. Every local and parameter they introduce is `__ts_`-prefixed, and
// `crate::hygiene::Locals` keeps those names clear of const parameters and of
// items in the caller's scope (the `other` parameter's dummy `fn` sits in the
// `const _: () = { ... };` block around the impls, the bindings' dummies at
// the top of `ts_eq`). The protected crate's items (`TimingSafeEq`, `Choice`) are
// named through its path, resolved per invocation by
// `crate_path::protected_crate_path`, so the derive works without a `use`
// whether the caller depends on `vitaminc-protected` (under any name) or on the
// `vitaminc` umbrella.
pub fn derive_timing_safe(input: DeriveInput) -> TokenStream {
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Parse `#[timing_safe(crate = "...")]`, the only key the derive accepts.
fn parse_crate_attr(input: &DeriveInput) -> syn::Result<Option<Path>> {
    let mut krate = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("timing_safe") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                krate = Some(parse_crate_value(&meta)?);
                return Ok(());
            }
            Err(meta.error("unsupported attribute; expected `crate = \"...\"`"))
        })?;
    }
    Ok(krate)
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let krate = protected_crate_path(parse_crate_attr(input)?, "timing_safe")?;
    let ident = &input.ident;
    let mut generics = input.generics.clone();

    // Collect all field types so we can require `TimingSafeEq` bounds on them.
    let field_types = collect_field_types(&input.data);

    // Extend the where-clause with `FieldTy: TimingSafeEq` for each unique field type.
    {
        let where_clause = generics.make_where_clause();
        for ty in field_types {
            where_clause
                .predicates
                .push(syn::parse_quote!(#ty: #krate::TimingSafeEq));
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let mut locals = Locals::new(input);
    let other = locals.param("__ts_other", Span::call_site());

    // --- body of TimingSafeEq::ts_eq ---
    let ts_body = match &input.data {
        Data::Struct(ds) => ts_body_struct(&krate, ds, &other, &mut locals),
        Data::Enum(de) => ts_body_enum(&krate, de, &other, &mut locals),
        // Unions are never equal: the derive cannot tell which field is live.
        Data::Union(_) => quote! {
            let _ = #other;
            #krate::Choice::from(0u8)
        },
    };
    let body_shadows = locals.body_shadows();
    let param_shadows = locals.param_shadows();

    Ok(quote! {
        const _: () = {
            #param_shadows

            #[automatically_derived]
            impl #impl_generics #krate::TimingSafeEq for #ident #ty_generics #where_clause {
                #[inline]
                fn ts_eq(&self, #other: &Self) -> #krate::Choice {
                    #body_shadows
                    #ts_body
                }
            }

            // --- impl PartialEq / Eq based on ts_eq ---
            #[automatically_derived]
            impl #impl_generics ::core::cmp::PartialEq for #ident #ty_generics #where_clause {
                #[inline]
                fn eq(&self, #other: &Self) -> bool {
                    #krate::TimingSafeEq::ts_eq(self, #other).into()
                }
            }

            #[automatically_derived]
            impl #impl_generics ::core::cmp::Eq for #ident #ty_generics #where_clause {}
        };
    })
}

fn collect_field_types(data: &syn::Data) -> Vec<Type> {
    use quote::ToTokens;
    use std::collections::BTreeSet;

    let mut set: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<Type> = Vec::new();

    let mut push_ty = |ty: &Type| {
        // De-dup roughly by token string (good enough for bounds generation)
        let s = ty.to_token_stream().to_string();
        if set.insert(s) {
            out.push(ty.clone());
        }
    };

    match data {
        Data::Struct(ds) => match &ds.fields {
            Fields::Named(named) => {
                for f in &named.named {
                    push_ty(&f.ty);
                }
            }
            Fields::Unnamed(unnamed) => {
                for f in &unnamed.unnamed {
                    push_ty(&f.ty);
                }
            }
            Fields::Unit => {}
        },
        Data::Enum(de) => {
            for v in &de.variants {
                match &v.fields {
                    Fields::Named(named) => {
                        for f in &named.named {
                            push_ty(&f.ty);
                        }
                    }
                    Fields::Unnamed(unnamed) => {
                        for f in &unnamed.unnamed {
                            push_ty(&f.ty);
                        }
                    }
                    Fields::Unit => {}
                }
            }
        }
        Data::Union(u) => {
            for f in &u.fields.named {
                push_ty(&f.ty);
            }
        }
    }
    out
}

/// The `(lhs, rhs) => fold` arm that compares two values of the same struct
/// or variant at `path` (`Self` or `Self::V`). Each field is bound by
/// reference on both sides, as `__ts_lhs_<index>` and `__ts_rhs_<index>`, and
/// the `ts_eq` results are combined with the non-short-circuiting `&`.
fn compare_arm(
    krate: &Path,
    path: proc_macro2::TokenStream,
    fields: &Fields,
    scope: &mut Scope<'_>,
) -> proc_macro2::TokenStream {
    let (lhs, rhs): (Vec<_>, Vec<_>) = (0..fields.len())
        .map(|i| {
            (
                scope.bind(&format!("__ts_lhs_{i}"), Span::call_site()),
                scope.bind(&format!("__ts_rhs_{i}"), Span::call_site()),
            )
        })
        .unzip();
    let (lhs_pat, rhs_pat) = match fields {
        Fields::Named(named) => {
            let names: Vec<_> = named.named.iter().map(|f| &f.ident).collect();
            (
                quote!(#path { #(#names: ref #lhs),* }),
                quote!(#path { #(#names: ref #rhs),* }),
            )
        }
        Fields::Unnamed(_) => (
            quote!(#path( #(ref #lhs),* )),
            quote!(#path( #(ref #rhs),* )),
        ),
        Fields::Unit => (path.clone(), path),
    };
    quote! {
        (#lhs_pat, #rhs_pat) => #krate::Choice::from(1u8)
            #( & #krate::TimingSafeEq::ts_eq(#lhs, #rhs) )*
    }
}

fn ts_body_struct(
    krate: &Path,
    ds: &DataStruct,
    other: &syn::Ident,
    locals: &mut Locals,
) -> proc_macro2::TokenStream {
    if let Fields::Unit = ds.fields {
        // Always equal (no secret-bearing fields)
        return quote! {
            let _ = #other;
            #krate::Choice::from(1u8)
        };
    }
    let arm = compare_arm(krate, quote!(Self), &ds.fields, &mut locals.scope());
    quote! {
        match (self, #other) {
            #arm
        }
    }
}

fn ts_body_enum(
    krate: &Path,
    de: &DataEnum,
    other: &syn::Ident,
    locals: &mut Locals,
) -> proc_macro2::TokenStream {
    // One arm per variant comparing same-variant fields. Arms cannot see each
    // other's bindings, so each gets its own scope.
    let arms = de.variants.iter().map(|v| {
        let v_ident = &v.ident;
        compare_arm(
            krate,
            quote!(Self::#v_ident),
            &v.fields,
            &mut locals.scope(),
        )
    });

    quote! {
        match (self, #other) {
            #(#arms,)*
            // Non-matching variants are not equal.
            _ => #krate::Choice::from(0u8),
        }
    }
}
