use proc_macro::TokenStream;
use quote::{quote, quote_spanned};
use syn::{Attribute, Data, DataEnum, DataStruct, DeriveInput, Fields, spanned::Spanned};

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

fn has_non_sensitive(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("non_sensitive"))
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
            // Use DebugStruct and decide per-field based on #[non_sensitive]
            let field_tokens = named.named.iter().map(|f| {
                let fname = f.ident.as_ref().unwrap();
                let key   = fname.to_string();
                if has_non_sensitive(&f.attrs) {
                    // show actual value
                    quote_spanned! { f.span() =>
                        ds.field(#key, &self.#fname);
                    }
                } else {
                    // mask
                    quote_spanned! { f.span() =>
                        ds.field(#key, &#mask);
                    }
                }
            });

            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        let mut ds = f.debug_struct(tn);
                        #(#field_tokens)*
                        ds.finish()
                    }
                }
            }
        }
        Fields::Unnamed(unnamed) => {
            // Use DebugTuple and decide per-field based on #[non_sensitive]
            let field_tokens = unnamed.unnamed.iter().enumerate().map(|(i, f)| {
                let idx = syn::Index::from(i);
                if has_non_sensitive(&f.attrs) {
                    quote_spanned! { f.span() =>
                        dt.field(&self.#idx);
                    }
                } else {
                    quote_spanned! { f.span() =>
                        dt.field(&#mask);
                    }
                }
            });

            quote! {
                impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        let mut dt = f.debug_tuple(tn);
                        #(#field_tokens)*
                        dt.finish()
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
    _impl_generics: &impl quote::ToTokens,
    ty_generics: &impl quote::ToTokens,
    _where_clause: Option<&syn::WhereClause>,
    mask: &str,
) -> proc_macro2::TokenStream {
    let mut arms = Vec::new();

    for v in &de.variants {
        let v_ident = &v.ident;
        let variant_ns = has_non_sensitive(&v.attrs);

        match &v.fields {
            syn::Fields::Unit => {
                arms.push(quote! {
                    Self::#v_ident => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{}", tn, ::core::stringify!(#v_ident))
                    }
                });
            }

            syn::Fields::Unnamed(fields) => {
                // bind each field by ref
                let bind_ids: Vec<syn::Ident> = (0..fields.unnamed.len())
                    .map(|i| syn::Ident::new(&format!("__f{}", i), v.span()))
                    .collect();

                let pat = quote! { #( ref #bind_ids ),* };

                // per-field write with commas and masking
                let writes = bind_ids.iter().enumerate().map(|(i, ident_i)| {
                    let comma = if i == 0 { "" } else { ", " };
                    let field_attrs = &fields.unnamed[i].attrs;
                    if variant_ns || has_non_sensitive(field_attrs) {
                        quote! { write!(f, concat!(#comma, "{:?}"), #ident_i)?; }
                    } else {
                        quote! { write!(f, concat!(#comma, "{:?}"), #mask)?; }
                    }
                });

                arms.push(quote! {
                    Self::#v_ident( #pat ) => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{}(", tn, ::core::stringify!(#v_ident))?;
                        #(#writes)*
                        write!(f, ")")
                    }
                });
            }

            syn::Fields::Named(fields) => {
                let ids: Vec<_> = fields.named.iter()
                    .map(|f| f.ident.as_ref().unwrap().clone())
                    .collect();

                let pat_bindings = ids.iter().map(|id| quote!(ref #id));

                // per-field write with key, commas, and masking
                let writes = fields.named.iter().enumerate().map(|(i, f)| {
                    let id = f.ident.as_ref().unwrap();
                    let key = id.to_string();
                    let prefix = if i == 0 { "" } else { ", " };
                    if variant_ns || has_non_sensitive(&f.attrs) {
                        quote! { write!(f, concat!(#prefix, #key, ": {:?}"), #id)?; }
                    } else {
                        quote! { write!(f, concat!(#prefix, #key, ": {:?}"), #mask)?; }
                    }
                });

                arms.push(quote! {
                    Self::#v_ident { #( #pat_bindings ),* } => {
                        let tn = ::core::any::type_name::<#ident #ty_generics>();
                        write!(f, "{}::{} {{", tn, ::core::stringify!(#v_ident))?;
                        #(#writes)*
                        write!(f, "}}")
                    }
                });
            }
        }
    }

    quote! {
        impl ::core::fmt::Debug for #ident #ty_generics {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    #(#arms),*
                }
            }
        }
    }
}
