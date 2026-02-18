use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields, Type};

pub fn derive_timing_safe(input: DeriveInput) -> TokenStream {
    let ident = input.ident.clone();
    let mut generics = input.generics.clone();

    // Collect all field types so we can require `TimingSafeEq` bounds on them.
    let field_types = collect_field_types(&input.data);

    // Extend the where-clause with `FieldTy: TimingSafeEq` for each unique field type.
    {
        let where_clause = generics.make_where_clause();
        for ty in field_types {
            where_clause
                .predicates
                .push(syn::parse_quote!(#ty: ::vitaminc_protected::TimingSafeEq));
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // --- impl TimingSafeEq ---
    let ts_impl = match &input.data {
        Data::Struct(ds) => ts_impl_struct(&ident, ds, &impl_generics, &ty_generics, where_clause),
        Data::Enum(de) => ts_impl_enum(&ident, de, &impl_generics, &ty_generics, where_clause),
        Data::Union(_) => {
            // For unions, provide a conservative implementation: only equal by reference identity is impossible here;
            // so we treat unions as unequal unless the type has no fields (which unions don't). Safer to refuse:
            // But to keep it compiling, return false (0). Adjust if you decide to support unions later.
            quote! {
                #[automatically_derived]
                impl #impl_generics TimingSafeEq for #ident #ty_generics #where_clause {
                    #[inline]
                    fn ts_eq(&self, _other: &Self) -> ::vitaminc_protected::Choice {
                        ::vitaminc_protected::Choice::from(0u8)
                    }
                }
            }
        }
    };

    // --- impl PartialEq / Eq based on ts_eq ---
    let pe_impl = quote! {
        #[automatically_derived]
        impl #impl_generics ::core::cmp::PartialEq for #ident #ty_generics #where_clause {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.ts_eq(other).into()
            }
        }
        impl #impl_generics ::core::cmp::Eq for #ident #ty_generics #where_clause {}
    };

    quote!(#ts_impl #pe_impl).into()
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

fn ts_impl_struct(
    ident: &syn::Ident,
    ds: &DataStruct,
    impl_generics: &impl quote::ToTokens,
    ty_generics: &impl quote::ToTokens,
    where_clause: Option<&syn::WhereClause>,
) -> proc_macro2::TokenStream {
    match &ds.fields {
        Fields::Named(named) => {
            // Bind each field by reference on both sides: { a: ref a1, b: ref b1 } vs { a: ref a2, b: ref b2 }
            let mut lhs_bind = Vec::new();
            let mut rhs_bind = Vec::new();
            let mut compares = Vec::new();

            for f in &named.named {
                let name = f.ident.as_ref().unwrap();
                let l = format_ident!("__ts_lhs_{}", name);
                let r = format_ident!("__ts_rhs_{}", name);
                lhs_bind.push(quote!( #name: ref #l ));
                rhs_bind.push(quote!( #name: ref #r ));
                compares.push(quote!( acc &= ::vitaminc_protected::TimingSafeEq::ts_eq(#l, #r); ));
            }

            quote! {
                #[automatically_derived]
                impl #impl_generics TimingSafeEq for #ident #ty_generics #where_clause {
                    #[inline]
                    fn ts_eq(&self, other: &Self) -> ::vitaminc_protected::Choice {
                        match (self, other) {
                            (
                                Self { #(#lhs_bind,)* },
                                Self { #(#rhs_bind,)* },
                            ) => {
                                let mut acc = ::vitaminc_protected::Choice::from(1u8);
                                #(#compares)*
                                acc
                            }
                        }
                    }
                }
            }
        }
        Fields::Unnamed(unnamed) => {
            // Tuple struct: (ref f0, ref f1, ...)
            let n = unnamed.unnamed.len();
            let lhs: Vec<_> = (0..n).map(|i| format_ident!("__ts_lhs_{}", i)).collect();
            let rhs: Vec<_> = (0..n).map(|i| format_ident!("__ts_rhs_{}", i)).collect();

            let compares: Vec<_> = lhs
                .iter()
                .zip(rhs.iter())
                .map(|(l, r)| quote!( acc &= ::vitaminc_protected::TimingSafeEq::ts_eq(#l, #r); ))
                .collect();

            quote! {
                #[automatically_derived]
                impl #impl_generics TimingSafeEq for #ident #ty_generics #where_clause {
                    #[inline]
                    fn ts_eq(&self, other: &Self) -> ::vitaminc_protected::Choice {
                        let Self( #(ref #lhs),* ) = self;
                        let Self( #(ref #rhs),* ) = other;
                        let mut acc = ::vitaminc_protected::Choice::from(1u8);
                        #(#compares)*
                        acc
                    }
                }
            }
        }
        Fields::Unit => {
            // Always equal (no secret-bearing fields)
            quote! {
                #[automatically_derived]
                impl #impl_generics TimingSafeEq for #ident #ty_generics #where_clause {
                    #[inline]
                    fn ts_eq(&self, _other: &Self) -> ::vitaminc_protected::Choice {
                        ::vitaminc_protected::Choice::from(1u8)
                    }
                }
            }
        }
    }
}

fn ts_impl_enum(
    ident: &syn::Ident,
    de: &DataEnum,
    impl_generics: &impl quote::ToTokens,
    ty_generics: &impl quote::ToTokens,
    where_clause: Option<&syn::WhereClause>,
) -> proc_macro2::TokenStream {
    // For each variant, generate a match arm that compares same-variant fields.
    let mut arms = Vec::new();

    for (vi, v) in de.variants.iter().enumerate() {
        let v_ident = &v.ident;
        match &v.fields {
            Fields::Named(named) => {
                let mut lbind = Vec::new();
                let mut rbind = Vec::new();
                let mut compares = Vec::new();

                for f in &named.named {
                    let fname = f.ident.as_ref().unwrap();
                    let l = format_ident!("__ts_lhs_{}_{}", vi, fname);
                    let r = format_ident!("__ts_rhs_{}_{}", vi, fname);
                    lbind.push(quote!( #fname: ref #l ));
                    rbind.push(quote!( #fname: ref #r ));
                    compares
                        .push(quote!( acc &= ::vitaminc_protected::TimingSafeEq::ts_eq(#l, #r); ));
                }
                arms.push(quote! {
                    (Self::#v_ident { #(#lbind,)* }, Self::#v_ident { #(#rbind,)* }) => {
                        let mut acc = ::vitaminc_protected::Choice::from(1u8);
                        #(#compares)*
                        acc
                    }
                });
            }
            Fields::Unnamed(unnamed) => {
                let n = unnamed.unnamed.len();
                let lhs: Vec<_> = (0..n)
                    .map(|fi| format_ident!("__ts_lhs_{}_{}", vi, fi))
                    .collect();
                let rhs: Vec<_> = (0..n)
                    .map(|fi| format_ident!("__ts_rhs_{}_{}", vi, fi))
                    .collect();
                let compares: Vec<_> = lhs.iter().zip(rhs.iter())
                    .map(|(l, r)| quote!( acc &= ::vitaminc_protected::TimingSafeEq::ts_eq(#l, #r); ))
                    .collect();
                arms.push(quote! {
                    (Self::#v_ident( #(ref #lhs),* ), Self::#v_ident( #(ref #rhs),* )) => {
                        let mut acc = ::vitaminc_protected::Choice::from(1u8);
                        #(#compares)*
                        acc
                    }
                });
            }
            Fields::Unit => {
                arms.push(quote! {
                    (Self::#v_ident, Self::#v_ident) => ::vitaminc_protected::Choice::from(1u8)
                });
            }
        }
    }

    // Non-matching variants are not equal.
    arms.push(quote! { _ => ::vitaminc_protected::Choice::from(0u8) });

    quote! {
        #[automatically_derived]
        impl #impl_generics TimingSafeEq for #ident #ty_generics #where_clause {
            #[inline]
            fn ts_eq(&self, other: &Self) -> ::vitaminc_protected::Choice {
                match (self, other) {
                    #(#arms),*
                }
            }
        }
    }
}
