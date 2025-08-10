use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields};

pub fn derive_opaque_debug(input: DeriveInput) -> TokenStream {
    let ident = input.ident.clone();
    let generics = input.generics.clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Only config is the mask string (default "***")
    let mask = parse_mask_attr(&input);

    let marker_impl = quote! {
        impl #impl_generics OpaqueDebug for #ident #ty_generics #where_clause {}
    };

    let dbg_impl = match &input.data {
        Data::Struct(ds) => debug_impl_for_struct(
            &ident,
            ds,
            &impl_generics,
            &ty_generics,
            where_clause,
            &mask,
        ),
        Data::Enum(de) => debug_impl_for_enum(
            &ident,
            de,
            &impl_generics,
            &ty_generics,
            where_clause,
            &mask,
        ),
        Data::Union(_) => {
            // For unions: just print the type name
            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        f.write_str(tn)
                    }
                }
            }
        }
    };

    quote!(#marker_impl #dbg_impl).into()
}

/// Parse `#[opaque_debug(mask = "...")]` using syn v2 `parse_nested_meta`.
fn parse_mask_attr(input: &DeriveInput) -> String {
    let mut mask = "***".to_string();

    for attr in &input.attrs {
        if !attr.path().is_ident("opaque_debug") {
            continue;
        }
        // Accept: #[opaque_debug(mask = "...")]
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("mask") {
                let lit: syn::LitStr = meta.value()?.parse()?;
                mask = lit.value();
                return Ok(());
            }
            // Unknown keys produce a nice error tied to the attribute span
            Err(meta.error("unsupported attribute; expected `mask = \"...\"`"))
        });
    }

    mask
}

fn debug_impl_for_struct(
    ident: &syn::Ident,
    ds: &DataStruct,
    impl_generics: &impl quote::ToTokens,
    ty_generics: &impl quote::ToTokens,
    where_clause: Option<&syn::WhereClause>,
    mask: &str,
) -> proc_macro2::TokenStream {
    match &ds.fields {
        Fields::Named(named) => {
            // Type { a: ***, b: *** }
            let mut parts = Vec::new();
            for (i, f) in named.named.iter().enumerate() {
                let name = f.ident.as_ref().unwrap();
                let comma = if i == 0 { "" } else { ", " };
                parts.push(format!("{}{}: {}", comma, name, mask));
            }
            let fmt_body = format!("{{ {} }}", parts.concat());

            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{} {}", tn, #fmt_body)
                    }
                }
            }
        }
        Fields::Unnamed(unnamed) => {
            // Type(***, ***, ...)
            let mut parts = Vec::new();
            for i in 0..unnamed.unnamed.len() {
                let comma = if i == 0 { "" } else { ", " };
                parts.push(format!("{}{}", comma, mask));
            }
            let fmt_body = format!("({})", parts.concat());

            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{} {}", tn, #fmt_body)
                    }
                }
            }
        }
        Fields::Unit => {
            // Type
            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        f.write_str(tn)
                    }
                }
            }
        }
    }
}

fn debug_impl_for_enum(
    ident: &syn::Ident,
    de: &DataEnum,
    impl_generics: &impl quote::ToTokens,
    ty_generics: &impl quote::ToTokens,
    where_clause: Option<&syn::WhereClause>,
    mask: &str,
) -> proc_macro2::TokenStream {
    let mut arms = Vec::new();

    for v in &de.variants {
        let v_ident = &v.ident;
        match &v.fields {
            Fields::Named(named) => {
                // Type::Variant { a: ***, b: *** }
                let mut parts = Vec::new();
                for (i, f) in named.named.iter().enumerate() {
                    let fname = f.ident.as_ref().unwrap();
                    let comma = if i == 0 { "" } else { ", " };
                    parts.push(format!("{}{}: {}", comma, fname, mask));
                }
                let body = format!("{{ {} }}", parts.concat());
                arms.push(quote! {
                    Self::#v_ident { .. } => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{} {}", tn, stringify!(#v_ident), #body)
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                // Type::Variant(***, ***)
                let mut parts = Vec::new();
                for i in 0..unnamed.unnamed.len() {
                    let comma = if i == 0 { "" } else { ", " };
                    parts.push(format!("{}{}", comma, mask));
                }
                let body = format!("({})", parts.concat());
                arms.push(quote! {
                    Self::#v_ident(..) => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{} {}", tn, stringify!(#v_ident), #body)
                    }
                });
            }
            Fields::Unit => {
                // Type::Variant
                arms.push(quote! {
                    Self::#v_ident => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{}", tn, stringify!(#v_ident))
                    }
                });
            }
        }
    }

    quote! {
        impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    #(#arms),*
                }
            }
        }
    }
}
