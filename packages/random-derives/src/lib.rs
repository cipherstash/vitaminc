use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

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
