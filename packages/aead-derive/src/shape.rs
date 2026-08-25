//! Classification of the derive input into the wire shape it maps onto.

use std::collections::HashMap;

use proc_macro2::Span;
use syn::{Data, DeriveInput, Fields, Ident, Member, Result, Type};

use crate::attrs::FieldAttrs;

/// One encrypted field of a struct.
#[cfg_attr(test, derive(Debug))]
pub(crate) struct FieldInfo {
    /// Map key this field is stored under — the field name, the decimal index
    /// for a tuple struct, or the `#[aead(rename = "...")]` override.
    pub(crate) key: String,
    /// How the field is reached on `self` (`self.name` or `self.0`).
    pub(crate) member: Member,
    /// A local binding name, unique per field, for use in generated bodies.
    /// Derived from the position so tuple fields get a legal identifier.
    pub(crate) local: Ident,
    pub(crate) ty: Type,
    /// `#[aead(passthrough)]`: stored in the clear, never encrypted and never
    /// authenticated.
    pub(crate) passthrough: bool,
    /// `#[aead(aad)]`: stored in the clear like a passthrough, but also bound
    /// into the associated data every encrypted field is sealed against, so
    /// editing it stops those fields opening.
    pub(crate) aad: bool,
    /// Whether [`key`](FieldInfo::key) came from `#[aead(rename = "...")]`
    /// rather than the field's own name. Only the newtype guard needs this —
    /// everywhere else the rename has already been folded into `key`.
    pub(crate) renamed: bool,
}

/// The wire shape a struct maps onto — see the crate docs.
#[cfg_attr(test, derive(Debug))]
pub(crate) enum Shape {
    /// Exactly one unnamed field: transparent, delegating to the inner type.
    /// Boxed to keep the variant from dominating the enum's size.
    Newtype(Box<FieldInfo>),
    /// One or more fields, encoded as a map keyed by [`FieldInfo::key`].
    Map(Vec<FieldInfo>),
    /// No fields at all: the authenticated empty-map marker.
    Empty,
}

impl Shape {
    pub(crate) fn parse(input: &DeriveInput) -> Result<Self> {
        let data = match &input.data {
            Data::Struct(data) => data,
            Data::Enum(_) => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "Encrypt/Decrypt cannot be derived for enums: a ciphertext carries no \
                     authenticated variant discriminator, so the variant would have to travel \
                     in the clear or be forgeable. Model the choice explicitly instead, e.g. as \
                     a struct of `Option` fields.",
                ))
            }
            Data::Union(_) => {
                return Err(syn::Error::new_spanned(
                    &input.ident,
                    "Encrypt/Decrypt cannot be derived for unions",
                ))
            }
        };

        let named = matches!(data.fields, Fields::Named(_));
        let fields = collect(&data.fields)?;

        // A newtype is transparent; a *named* one-field struct is not, since
        // its field name is a meaningful part of the wire contract.
        if !named && fields.len() == 1 {
            let mut fields = fields;
            let field = fields.remove(0);
            reject_newtype_field_attrs(&field, input)?;
            return Ok(Shape::Newtype(Box::new(field)));
        }

        if fields.is_empty() {
            return Ok(Shape::Empty);
        }

        reject_duplicate_keys(&fields, input)?;
        reject_conflicting_cleartext_attrs(&fields, input)?;
        reject_all_cleartext(&fields, input)?;
        Ok(Shape::Map(fields))
    }
}

impl FieldInfo {
    /// Whether the field is stored in the clear rather than encrypted. Both
    /// `passthrough` and `aad` fields are; they differ only in whether the
    /// stored bytes are bound into the encrypted fields' associated data.
    pub(crate) fn is_cleartext(&self) -> bool {
        self.passthrough || self.aad
    }
}

fn collect(fields: &Fields) -> Result<Vec<FieldInfo>> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let attrs = FieldAttrs::parse(&field.attrs)?;
            let renamed = attrs.rename.is_some();
            let (key, member) = match &field.ident {
                Some(ident) => (ident.to_string(), Member::Named(ident.clone())),
                None => (index.to_string(), Member::Unnamed(syn::Index::from(index))),
            };
            Ok(FieldInfo {
                key: attrs.rename.unwrap_or(key),
                member,
                local: Ident::new(&format!("__field_{index}"), Span::call_site()),
                ty: field.ty.clone(),
                passthrough: attrs.passthrough,
                aad: attrs.aad,
                renamed,
            })
        })
        .collect()
}

/// Two fields sharing a map key would silently overwrite one another on
/// encrypt (and the decipher rejects duplicate keys anyway), so catch it here
/// where the error can point at the offending `rename`.
fn reject_duplicate_keys(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    let mut seen: HashMap<&str, ()> = HashMap::with_capacity(fields.len());
    for field in fields {
        if seen.insert(field.key.as_str(), ()).is_some() {
            return Err(syn::Error::new_spanned(
                &input.ident,
                format!(
                    "duplicate map key `{}`: two fields would be encrypted under the same key",
                    field.key
                ),
            ));
        }
    }
    Ok(())
}

/// A newtype is transparent: it encrypts exactly as its inner type, opening no
/// map and producing no entry. Every field attribute the derive understands
/// describes a map entry, so on a newtype there is nothing for one to describe.
///
/// Both are rejected rather than ignored, because ignoring them is silent and
/// the author's intent was the opposite of what they would get. `rename` names
/// a map key that is never written, so a value the author believes is
/// key-bound has no key binding at all. `passthrough` asks for a cleartext
/// entry that does not exist; honouring it instead would mean the whole value
/// travels unencrypted, leaving a container with no tag — the same thing
/// `MapCipher::end` refuses to seal.
fn reject_newtype_field_attrs(field: &FieldInfo, input: &DeriveInput) -> Result<()> {
    if field.renamed {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(rename = \"...\")]` has no effect on a newtype struct: a newtype is \
             transparent, so its value is not stored under a map key at all and there is no \
             key to rename. Give the struct a named field instead.",
        ));
    }
    if field.passthrough {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(passthrough)]` is meaningless on a newtype struct: a newtype is \
             transparent, so there is no map entry to store in the clear and nothing \
             would be encrypted at all. Give the struct a named field instead.",
        ));
    }
    if field.aad {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`#[aead(aad)]` is meaningless on a newtype struct: a newtype is transparent, \
             so there is no map entry to store the value in the clear and no other field \
             for it to be bound to. Give the struct a named field instead.",
        ));
    }
    Ok(())
}

/// A map with no encrypted entries carries no tag at all — nothing
/// authenticates the map's AAD, and nothing binds the entry keys — so
/// `MapCipher::end` rejects one at seal time. Catch it here, where the error
/// names the struct instead of surfacing as a runtime encrypt failure.
fn reject_all_cleartext(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    if fields.iter().all(FieldInfo::is_cleartext) {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "every field is stored in the clear (`#[aead(passthrough)]` or `#[aead(aad)]`), so \
             nothing would be encrypted and the ciphertext would carry no tag — neither the \
             associated data nor the entry keys would be authenticated. An `aad` field binds \
             encrypted fields to itself, so it needs at least one to bind. Encrypt at least \
             one field, or do not derive Encrypt for this struct at all.",
        ));
    }
    Ok(())
}

/// `aad` already stores the field in the clear — it is `passthrough` plus the
/// binding. Accepting both would leave the author guessing which won.
fn reject_conflicting_cleartext_attrs(fields: &[FieldInfo], input: &DeriveInput) -> Result<()> {
    for field in fields {
        if field.passthrough && field.aad {
            return Err(syn::Error::new_spanned(
                &input.ident,
                format!(
                    "field `{}` is both `#[aead(passthrough)]` and `#[aead(aad)]`: `aad` \
                     already stores the value in the clear, and additionally binds it into \
                     the associated data. Use one or the other.",
                    field.key
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    /// Enums have no authenticated variant discriminator, so the macro must
    /// refuse them outright rather than pick an encoding — see the crate docs.
    #[test]
    fn enums_are_rejected() {
        let input: DeriveInput = parse_quote! {
            enum Choice {
                A(String),
                B(u32),
            }
        };
        let err = Shape::parse(&input).expect_err("enum should be rejected");
        assert!(err.to_string().contains("cannot be derived for enums"));
    }

    #[test]
    fn unions_are_rejected() {
        let input: DeriveInput = parse_quote! {
            union Raw {
                a: u32,
                b: u32,
            }
        };
        assert!(Shape::parse(&input).is_err());
    }

    /// Two fields renamed onto one key would overwrite each other on encrypt
    /// and be rejected as duplicates on decrypt; catch it at compile time.
    #[test]
    fn duplicate_keys_are_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Clash {
                a: String,
                #[aead(rename = "a")]
                b: String,
            }
        };
        let err = Shape::parse(&input).expect_err("duplicate key should be rejected");
        assert!(err.to_string().contains("duplicate map key `a`"));
    }

    /// A map with no encrypted entries carries no tag at all, and
    /// `MapCipher::end` rejects one at seal time — so catch it at compile time.
    #[test]
    fn an_all_passthrough_struct_is_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(passthrough)]
                id: i64,
                #[aead(passthrough)]
                tenant: String,
            }
        };
        let err = Shape::parse(&input).expect_err("all-passthrough struct should be rejected");
        assert!(err.to_string().contains("nothing would be encrypted"));
    }

    /// A newtype's value is not stored under a map key, so a `rename` names a
    /// key that is never written. Ignoring it would leave the author believing
    /// the value is key-bound when nothing binds it at all.
    #[test]
    fn rename_on_a_newtype_is_rejected() {
        let input: DeriveInput = parse_quote!(
            struct Token(#[aead(rename = "token")] String);
        );
        let err = Shape::parse(&input).expect_err("renamed newtype should be rejected");
        assert!(err.to_string().contains("no effect on a newtype"));
    }

    /// `aad` is `passthrough` plus a binding, so asking for both leaves the
    /// author guessing which won.
    #[test]
    fn aad_and_passthrough_on_one_field_is_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(aad, passthrough)]
                term: Vec<u8>,
                ssn: String,
            }
        };
        let err = Shape::parse(&input).expect_err("conflicting attributes should be rejected");
        assert!(err
            .to_string()
            .contains("already stores the value in the clear"));
    }

    /// An `aad` field binds encrypted fields to itself, so a struct of nothing
    /// but cleartext has neither anything to bind nor any tag at all.
    #[test]
    fn a_struct_of_only_cleartext_fields_is_rejected() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(aad)]
                term: Vec<u8>,
                #[aead(passthrough)]
                id: i64,
            }
        };
        let err = Shape::parse(&input).expect_err("all-cleartext struct should be rejected");
        assert!(err.to_string().contains("nothing would be encrypted"));
    }

    /// A newtype is transparent: nothing is stored under a key, and there is no
    /// sibling field for the value to be bound to.
    #[test]
    fn aad_on_a_newtype_is_rejected() {
        let input: DeriveInput = parse_quote!(
            struct Term(#[aead(aad)] Vec<u8>);
        );
        let err = Shape::parse(&input).expect_err("aad newtype should be rejected");
        assert!(err.to_string().contains("meaningless on a newtype"));
    }

    /// A newtype is transparent, so there is no map entry for a passthrough to
    /// occupy. Silently ignoring the attribute would leave the author believing
    /// a field is stored in the clear when the whole value is encrypted.
    #[test]
    fn passthrough_on_a_newtype_is_rejected() {
        let input: DeriveInput = parse_quote!(
            struct Wrapper(#[aead(passthrough)] String);
        );
        let err = Shape::parse(&input).expect_err("passthrough newtype should be rejected");
        assert!(err.to_string().contains("meaningless on a newtype"));
    }

    /// A mixed struct is the shape the attribute exists for: some columns in
    /// the clear, at least one encrypted.
    #[test]
    fn a_mixed_struct_records_which_fields_are_passthrough() {
        let input: DeriveInput = parse_quote! {
            struct Row {
                #[aead(passthrough)]
                id: i64,
                ssn: String,
            }
        };
        match Shape::parse(&input) {
            Ok(Shape::Map(fields)) => {
                assert!(fields[0].passthrough);
                assert!(!fields[1].passthrough);
            }
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn single_unnamed_field_is_a_transparent_newtype() {
        let input: DeriveInput = parse_quote!(
            struct Wrapper(String);
        );
        assert!(matches!(Shape::parse(&input), Ok(Shape::Newtype(_))));
    }

    /// A *named* single-field struct is not transparent: its field name is
    /// part of the wire contract.
    #[test]
    fn single_named_field_is_a_map() {
        let input: DeriveInput = parse_quote! {
            struct Wrapper {
                inner: String,
            }
        };
        match Shape::parse(&input) {
            Ok(Shape::Map(fields)) => assert_eq!(fields[0].key, "inner"),
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn tuple_fields_are_keyed_by_index() {
        let input: DeriveInput = parse_quote!(
            struct Pair(String, u32);
        );
        match Shape::parse(&input) {
            Ok(Shape::Map(fields)) => {
                assert_eq!(fields[0].key, "0");
                assert_eq!(fields[1].key, "1");
            }
            _ => panic!("expected a map shape"),
        }
    }

    #[test]
    fn field_less_structs_are_empty() {
        let inputs: [DeriveInput; 3] = [
            parse_quote!(
                struct Unit;
            ),
            parse_quote!(
                struct Braced {}
            ),
            parse_quote!(
                struct Parens();
            ),
        ];
        for input in inputs {
            assert!(matches!(Shape::parse(&input), Ok(Shape::Empty)));
        }
    }
}
