//! Parsing of the `#[aead(...)]` container and field attributes.

use syn::{Attribute, Path, Result, Type};

/// Container-level options, from `#[aead(...)]` on the struct itself.
pub(crate) struct ContainerAttrs {
    /// Path to the `vitaminc_aead` crate in the generated code. Defaults to
    /// `::vitaminc_aead`; overridden by `#[aead(crate = "...")]` so the macros
    /// work through a re-export such as `::vitaminc::aead`.
    pub(crate) krate: Path,
    /// `#[aead(take)]`: read each field with `mem::take(&mut self.field)`
    /// instead of moving it out of `self`. A type with a `Drop` impl —
    /// `ZeroizeOnDrop` in particular — cannot be moved out of, and this is
    /// the shape a secret-holding newtype takes.
    pub(crate) take: bool,
    /// `#[aead(into = "T")]`: encrypt `Self` by converting it to `T` and
    /// encrypting that. The struct's own fields are not touched.
    pub(crate) into: Option<Type>,
    /// `#[aead(try_from = "T")]`: decrypt a `T` and convert it into `Self`
    /// with `TryFrom`, reporting a failed conversion as `Unspecified`.
    pub(crate) try_from: Option<Type>,
    /// `#[aead(from = "T")]`: decrypt a `T` and convert it into `Self` with
    /// `From`.
    pub(crate) from: Option<Type>,
}

impl ContainerAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut krate: Option<Path> = None;
        let mut take = false;
        let mut into: Option<Type> = None;
        let mut try_from: Option<Type> = None;
        let mut from: Option<Type> = None;

        for attr in attrs.iter().filter(|a| a.path().is_ident("aead")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("crate") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    krate = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("take") {
                    take = true;
                    return Ok(());
                }
                if meta.path.is_ident("into") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    into = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("try_from") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    try_from = Some(lit.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("from") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    from = Some(lit.parse()?);
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported container attribute; expected `crate = \"...\"`, `take`, \
                     `into = \"...\"`, `try_from = \"...\"` or `from = \"...\"`",
                ))
            })?;
        }

        // `take` reads the fields and `into` never looks at them, so both at
        // once means one of them is not doing what the author believes.
        if take && into.is_some() {
            return Err(syn::Error::new_spanned(
                attrs.iter().find(|a| a.path().is_ident("aead")).unwrap(),
                "`#[aead(take)]` and `#[aead(into = \"...\")]` cannot be combined: `into` \
                 converts the whole value and never reads the fields, so there is nothing for \
                 `take` to take. Use one or the other.",
            ));
        }
        if try_from.is_some() && from.is_some() {
            return Err(syn::Error::new_spanned(
                attrs.iter().find(|a| a.path().is_ident("aead")).unwrap(),
                "`#[aead(try_from = \"...\")]` and `#[aead(from = \"...\")]` cannot be \
                 combined: both name the type to decrypt as, and only one conversion can run. \
                 Use `try_from` if the conversion can fail, `from` if it cannot.",
            ));
        }

        Ok(Self {
            krate: krate.unwrap_or_else(|| syn::parse_quote!(::vitaminc_aead)),
            take,
            into,
            try_from,
            from,
        })
    }
}

/// Field-level options, from `#[aead(...)]` on a field.
pub(crate) struct FieldAttrs {
    /// Map key to use for this field, from `#[aead(rename = "...")]`.
    pub(crate) rename: Option<String>,
    /// Store this field in the clear rather than encrypting it, from
    /// `#[aead(passthrough)]`. The value is neither encrypted nor
    /// authenticated — see the crate docs.
    pub(crate) passthrough: bool,
}

impl FieldAttrs {
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut rename: Option<String> = None;
        let mut passthrough = false;

        for attr in attrs.iter().filter(|a| a.path().is_ident("aead")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    let lit: syn::LitStr = meta.value()?.parse()?;
                    rename = Some(lit.value());
                    return Ok(());
                }
                if meta.path.is_ident("passthrough") {
                    passthrough = true;
                    return Ok(());
                }
                Err(meta.error(
                    "unsupported field attribute; expected `rename = \"...\"` or `passthrough`",
                ))
            })?;
        }

        Ok(Self {
            rename,
            passthrough,
        })
    }
}
