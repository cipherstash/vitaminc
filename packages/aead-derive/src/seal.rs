//! **SPIKE.** `#[derive(Seal)]`: the typed counterpart of a struct, with
//! each sealed field a ciphertext node and each passthrough field kept as
//! its own type.
//!
//! The spike supports structs with named fields and no generics.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, Result};

use crate::attrs::ContainerAttrs;
use crate::shape::{FieldInfo, Shape};

pub(crate) fn derive(input: DeriveInput) -> Result<TokenStream> {
    let attrs = ContainerAttrs::parse(&input.attrs)?;
    let krate = &attrs.krate;
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "the `Seal` spike supports structs without generics only",
        ));
    }
    let named = matches!(
        &input.data,
        syn::Data::Struct(data) if matches!(data.fields, syn::Fields::Named(_))
    );
    let fields = match Shape::parse(&input)? {
        Shape::Map(fields) if named => fields,
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "the `Seal` spike supports structs with named fields only",
            ))
        }
    };

    let vis = &input.vis;
    let name = &input.ident;
    let sealed_name = format_ident!("Sealed{}", name);
    let sealed_ref_name = format_ident!("Sealed{}Ref", name);
    let stored: Vec<&FieldInfo> = fields.iter().filter(|f| f.stored()).collect();
    let sealed_count = stored.iter().filter(|f| f.sealed()).count();

    // The two struct definitions.
    let owned_fields = stored.iter().map(|f| {
        let member = &f.member;
        let ty = &f.ty;
        if f.passthrough {
            quote!(pub #member: #ty)
        } else {
            quote!(pub #member: #krate::Node<__L>)
        }
    });
    let ref_fields = stored.iter().map(|f| {
        let member = &f.member;
        let ty = &f.ty;
        if f.passthrough {
            quote!(pub #member: &'__r #ty)
        } else {
            quote!(pub #member: #krate::Node<__L>)
        }
    });

    // Every field out of the record into a local first, so each is moved
    // (or taken) exactly once whatever the struct implements.
    let owned_locals = fields.iter().map(|f| {
        let member = &f.member;
        let local = &f.local;
        if f.take {
            quote!(let #local = ::core::mem::take(&mut __this.#member);)
        } else {
            quote!(let #local = __this.#member;)
        }
    });
    let owned_locals: Vec<TokenStream> = owned_locals.collect();
    let plan_owned = stored.iter().filter(|f| f.sealed()).map(|f| {
        let key = &f.key;
        let local = &f.local;
        quote!(__plan.field(#key, #local)?;)
    });
    let plan_owned: Vec<TokenStream> = plan_owned.collect();
    let plan_ref = stored.iter().filter(|f| f.sealed()).map(|f| {
        let key = &f.key;
        let member = &f.member;
        quote!(__plan.field(#key, &self.#member)?;)
    });
    let build_owned: Vec<TokenStream> = stored
        .iter()
        .map(|f| {
            let member = &f.member;
            let local = &f.local;
            if f.passthrough {
                quote!(#member: #local)
            } else {
                quote!(#member: __sealed.next_field()?)
            }
        })
        .collect();
    let build_ref = stored.iter().map(|f| {
        let member = &f.member;
        if f.passthrough {
            quote!(#member: &self.#member)
        } else {
            quote!(#member: __sealed.next_field()?)
        }
    });

    // Opening: the sealed fields in order, then the record.
    let open_entries: Vec<TokenStream> = stored
        .iter()
        .filter(|f| f.sealed())
        .map(|f| {
            let key = &f.key;
            let member = &f.member;
            quote!((::std::string::String::from(#key), self.#member))
        })
        .collect();
    let open_build: Vec<TokenStream> = fields
        .iter()
        .map(|f| {
            let member = &f.member;
            if f.skip {
                quote!(#member: ::core::default::Default::default())
            } else if f.passthrough {
                quote!(#member: self.#member)
            } else {
                quote!(#member: __opened.field::<_, __C::Error>()?)
            }
        })
        .collect();

    // The dynamic tree: every stored field in declaration order, with each
    // passthrough framed.
    let node_entries = |borrowed: bool| -> Vec<TokenStream> {
        stored
            .iter()
            .map(|f| {
                let key = &f.key;
                let member = &f.member;
                let value = if f.passthrough {
                    let at = if borrowed {
                        quote!(self.#member)
                    } else {
                        quote!(&self.#member)
                    };
                    quote!(#krate::CipherText::Passthrough(#krate::record::frame_field(#at)?))
                } else {
                    quote!(self.#member)
                };
                quote!((::std::string::String::from(#key), #value))
            })
            .collect()
    };
    let owned_node_entries = node_entries(false);
    let ref_node_entries = node_entries(true);

    let sealed_doc = format!(
        "**SPIKE.** [`{name}`], sealed: each sealed field is a ciphertext node, and each \
         passthrough field is moved across as its own type. Made by `Seal::seal`."
    );
    let sealed_ref_doc = format!(
        "**SPIKE.** A borrowed [`{name}`], sealed: each sealed field is a ciphertext node, \
         and each passthrough field is borrowed from the record. Made by `Seal::seal_ref`."
    );

    Ok(quote! {
        #[doc = #sealed_doc]
        #[allow(missing_docs)]
        #vis struct #sealed_name<__L> {
            #(#owned_fields,)*
        }

        #[doc = #sealed_ref_doc]
        #[allow(missing_docs)]
        #vis struct #sealed_ref_name<'__r, __L> {
            #(#ref_fields,)*
        }

        impl #krate::record::Seal for #name {
            type Sealed<__L> = #sealed_name<__L>;
            type SealedRef<'__r, __L> = #sealed_ref_name<'__r, __L>;

            #[allow(unused_mut, unused_variables)]
            fn seal<'__a, __C: #krate::Cipher>(
                self,
                cipher: &__C,
                aad: impl #krate::IntoAad<'__a>,
            ) -> ::core::result::Result<#sealed_name<__C::Leaf>, #krate::EncryptError<__C::Error>> {
                let mut __this = self;
                #(#owned_locals)*
                let mut __plan = #krate::record::RecordPlan::new(aad, #sealed_count)?;
                #(#plan_owned)*
                let mut __sealed = #krate::record::seal_record(cipher, __plan.finish()?)?;
                ::core::result::Result::Ok(#sealed_name { #(#build_owned,)* })
            }

            fn seal_ref<'__r, '__a, __C: #krate::Cipher>(
                &'__r self,
                cipher: &__C,
                aad: impl #krate::IntoAad<'__a>,
            ) -> ::core::result::Result<
                #sealed_ref_name<'__r, __C::Leaf>,
                #krate::EncryptError<__C::Error>,
            > {
                let mut __plan = #krate::record::RecordPlan::new(aad, #sealed_count)?;
                #(#plan_ref)*
                let mut __sealed = #krate::record::seal_record(cipher, __plan.finish()?)?;
                ::core::result::Result::Ok(#sealed_ref_name { #(#build_ref,)* })
            }

            #[allow(unused_mut, unused_variables)]
            fn seal_async<'__a, __C: #krate::AsyncCipher>(
                self,
                cipher: &__C,
                aad: impl #krate::IntoAad<'__a>,
            ) -> impl ::core::future::Future<
                Output = ::core::result::Result<
                    #sealed_name<__C::Leaf>,
                    #krate::EncryptError<__C::Error>,
                >,
            > {
                let mut __this = self;
                #(#owned_locals)*
                // Planned now, so the future holds the planned leaves and
                // the passthrough fields, not the sealed fields' plaintext.
                let __planned = (|| -> ::core::result::Result<
                    #krate::Node<#krate::Pending>,
                    #krate::EncryptError<__C::Error>,
                > {
                    let mut __plan = #krate::record::RecordPlan::new(aad, #sealed_count)?;
                    #(#plan_owned)*
                    __plan.finish()
                })();
                async move {
                    let mut __sealed =
                        #krate::record::seal_record_async(cipher, __planned?).await?;
                    ::core::result::Result::Ok(#sealed_name { #(#build_owned,)* })
                }
            }
        }

        impl<__L> #sealed_name<__L> {
            /// Open the sealed fields in one batch and move the passthrough
            /// fields back into the record.
            ///
            /// # Errors
            ///
            /// As `vitaminc_aead::decrypt`.
            pub fn open<'__a, __C: #krate::Cipher<Leaf = __L>>(
                self,
                cipher: &__C,
                aad: impl #krate::IntoAad<'__a>,
            ) -> ::core::result::Result<
                #name,
                #krate::DecryptError<#krate::DecodeError, __C::Error>,
            > {
                let mut __opened =
                    #krate::record::open_record(cipher, ::std::vec![#(#open_entries),*], aad)?;
                ::core::result::Result::Ok(#name { #(#open_build,)* })
            }

            /// [`open`](Self::open) through an async cipher, in one
            /// `open_many` call.
            ///
            /// # Errors
            ///
            /// As `vitaminc_aead::decrypt_async`.
            pub async fn open_async<'__a, __C: #krate::AsyncCipher<Leaf = __L>>(
                self,
                cipher: &__C,
                aad: impl #krate::IntoAad<'__a>,
            ) -> ::core::result::Result<
                #name,
                #krate::DecryptError<#krate::DecodeError, __C::Error>,
            > {
                let mut __opened = #krate::record::open_record_async(
                    cipher,
                    ::std::vec![#(#open_entries),*],
                    aad,
                )
                .await?;
                ::core::result::Result::Ok(#name { #(#open_build,)* })
            }

            /// The dynamic tree `vitaminc_aead::encrypt` would have made.
            /// Each passthrough field is framed here, and only here.
            ///
            /// # Errors
            ///
            /// A passthrough too deep or too long for a frame.
            pub fn into_node(
                self,
            ) -> ::core::result::Result<
                #krate::Node<__L>,
                #krate::EncryptError<::core::convert::Infallible>,
            > {
                ::core::result::Result::Ok(#krate::CipherText::Map(::std::vec![
                    #(#owned_node_entries),*
                ]))
            }
        }

        impl<'__r, __L> #sealed_ref_name<'__r, __L> {
            /// The dynamic tree `vitaminc_aead::encrypt` would have made.
            /// Each passthrough field is framed from its borrow here, and
            /// only here.
            ///
            /// # Errors
            ///
            /// A passthrough too deep or too long for a frame.
            pub fn into_node(
                self,
            ) -> ::core::result::Result<
                #krate::Node<__L>,
                #krate::EncryptError<::core::convert::Infallible>,
            > {
                ::core::result::Result::Ok(#krate::CipherText::Map(::std::vec![
                    #(#ref_node_entries),*
                ]))
            }
        }
    })
}
