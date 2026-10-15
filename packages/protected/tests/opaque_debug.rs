//! `#[derive(OpaqueDebug)]` on generic types, and its hygiene.
//!
//! The derive must carry the type's lifetimes, type parameters, const
//! parameters and where clause onto both impls it emits, and nothing it
//! generates may be captured by names at the call site. A type that fails to
//! compile here is the regression: these tests mostly prove that the derive
//! expands at all, then pin the masked output shape.

// Masked struct fields are never read: the derived `Debug` writes the mask in
// their place, which is the point.
#![allow(dead_code)]
// The lowercase const parameters below are deliberate. On rustc 1.96 the lint
// also fires on the derived impls, which copy the parameters and sit outside
// any item-level `#[allow]`; `#[automatically_derived]` on those impls does not
// silence it. So it is allowed for the whole file.
#![allow(non_upper_case_globals)]

use core::any::type_name;
use core::fmt::Debug;
use vitaminc_protected::OpaqueDebug;

fn assert_opaque<T: OpaqueDebug + Debug>(_: &T) {}

fn assert_opaque_impl<T: OpaqueDebug + Debug + ?Sized>() {}

/// Implements neither `Debug` nor anything else.
struct NoDebug;

#[derive(OpaqueDebug)]
enum Physical<'a> {
    Text(&'a str),
    Pair { left: &'a str, right: &'a str },
    Null,
}

#[derive(OpaqueDebug)]
enum Labelled<T>
where
    T: Clone,
{
    Secret(T),
    #[non_sensitive]
    Visible(T),
    Named {
        hidden: T,
        #[non_sensitive]
        shown: T,
    },
}

#[derive(OpaqueDebug)]
enum Fixed<const N: usize> {
    Bytes([u8; N]),
}

#[derive(OpaqueDebug)]
struct Borrowed<'a> {
    secret: &'a str,
    #[non_sensitive]
    label: &'a str,
}

#[derive(OpaqueDebug)]
struct BorrowedTuple<'a>(&'a [u8]);

#[derive(OpaqueDebug)]
struct Holder<'a, T>
where
    T: ?Sized + Debug,
{
    #[non_sensitive]
    shown: &'a T,
    hidden: &'a T,
}

#[test]
fn enum_with_lifetime_masks_every_variant() {
    let tn = type_name::<Physical<'static>>();
    let owned = String::from("do-not-print");

    let text = Physical::Text(&owned);
    assert_opaque(&text);
    assert_eq!(format!("{text:?}"), format!("{tn}::Text(\"***\")"));

    let pair = Physical::Pair {
        left: &owned,
        right: &owned,
    };
    assert_eq!(
        format!("{pair:?}"),
        format!("{tn}::Pair {{ left: \"***\", right: \"***\" }}")
    );

    assert_eq!(format!("{:?}", Physical::Null), format!("{tn}::Null"));
}

#[test]
fn enum_with_type_param_and_where_clause_honours_non_sensitive() {
    let tn = type_name::<Labelled<u32>>();

    let secret = Labelled::Secret(7u32);
    assert_opaque(&secret);
    assert_eq!(format!("{secret:?}"), format!("{tn}::Secret(\"***\")"));

    let visible = Labelled::Visible(7u32);
    assert_eq!(format!("{visible:?}"), format!("{tn}::Visible(7)"));

    let named = Labelled::Named {
        hidden: 1u32,
        shown: 2u32,
    };
    assert_eq!(
        format!("{named:?}"),
        format!("{tn}::Named {{ hidden: \"***\", shown: 2 }}")
    );
}

#[test]
fn enum_with_const_generic_masks_field() {
    let bytes = Fixed::<4>::Bytes([1, 2, 3, 4]);
    assert_opaque(&bytes);
    let tn = type_name::<Fixed<4>>();
    assert!(tn.ends_with("Fixed<4>"));
    assert_eq!(format!("{bytes:?}"), format!("{tn}::Bytes(\"***\")"));
}

#[test]
fn struct_with_lifetime_masks_sensitive_fields() {
    let tn = type_name::<Borrowed<'static>>();
    let owned = String::from("do-not-print");

    let named = Borrowed {
        secret: &owned,
        label: "ok-to-print",
    };
    assert_opaque(&named);
    assert_eq!(
        format!("{named:?}"),
        format!("{tn} {{ secret: \"***\", label: \"ok-to-print\" }}")
    );

    let tuple = BorrowedTuple(owned.as_bytes());
    assert_opaque(&tuple);
    let tn = type_name::<BorrowedTuple<'static>>();
    assert_eq!(format!("{tuple:?}"), format!("{tn}(\"***\")"));
}

#[test]
fn struct_with_lifetime_type_param_and_where_clause() {
    let tn = type_name::<Holder<'static, str>>();
    let holder: Holder<'_, str> = Holder {
        shown: "ok-to-print",
        hidden: "do-not-print",
    };
    assert_opaque(&holder);
    let out = format!("{holder:?}");
    assert_eq!(
        out,
        format!("{tn} {{ shown: \"ok-to-print\", hidden: \"***\" }}")
    );
    assert!(!out.contains("do-not-print"));
}

// Enum variants go through `debug_struct`/`debug_tuple`, so `{:#?}` gives the
// same multi-line layout as a struct.
#[test]
fn enum_variant_honours_alternate_flag() {
    let tn = type_name::<Labelled<u32>>();
    let named = Labelled::Named {
        hidden: 1u32,
        shown: 2u32,
    };
    assert_eq!(
        format!("{named:#?}"),
        format!("{tn}::Named {{\n    hidden: \"***\",\n    shown: 2,\n}}")
    );

    let visible = Labelled::Visible(7u32);
    assert_eq!(
        format!("{visible:#?}"),
        format!("{tn}::Visible(\n    7,\n)")
    );
}

// The derive adds `FieldTy: Debug` only for fields it formats, so a fully
// masked generic type takes a non-`Debug` argument, and a `#[non_sensitive]`
// generic field needs no bound written by hand.
#[derive(OpaqueDebug)]
enum MaskedOnly<T> {
    Tuple(T),
    Named { inner: T },
}

#[derive(OpaqueDebug)]
struct MaskedOnlyStruct<T> {
    inner: T,
}

#[derive(OpaqueDebug)]
struct MaskedOnlyTuple<T>(T);

#[derive(OpaqueDebug)]
enum ShownUnbounded<T, U> {
    #[non_sensitive]
    Visible(T),
    Mixed {
        #[non_sensitive]
        shown: T,
        hidden: U,
    },
}

#[derive(OpaqueDebug)]
struct ShownUnboundedStruct<T, U> {
    #[non_sensitive]
    shown: T,
    hidden: U,
}

#[test]
fn masked_generic_fields_need_no_debug_bound() {
    let tn = type_name::<MaskedOnly<NoDebug>>();

    let tuple = MaskedOnly::Tuple(NoDebug);
    assert_opaque(&tuple);
    assert_eq!(format!("{tuple:?}"), format!("{tn}::Tuple(\"***\")"));

    let named = MaskedOnly::Named { inner: NoDebug };
    assert_eq!(
        format!("{named:?}"),
        format!("{tn}::Named {{ inner: \"***\" }}")
    );

    let s = MaskedOnlyStruct { inner: NoDebug };
    assert_opaque(&s);
    let tn = type_name::<MaskedOnlyStruct<NoDebug>>();
    assert_eq!(format!("{s:?}"), format!("{tn} {{ inner: \"***\" }}"));

    let t = MaskedOnlyTuple(NoDebug);
    assert_opaque(&t);
    let tn = type_name::<MaskedOnlyTuple<NoDebug>>();
    assert_eq!(format!("{t:?}"), format!("{tn}(\"***\")"));
}

#[test]
fn shown_generic_fields_get_a_debug_bound_without_one_written() {
    // `U` stays non-`Debug`: only the shown parameter is bounded.
    let tn = type_name::<ShownUnbounded<u32, NoDebug>>();

    let visible: ShownUnbounded<u32, NoDebug> = ShownUnbounded::Visible(7);
    assert_opaque(&visible);
    assert_eq!(format!("{visible:?}"), format!("{tn}::Visible(7)"));

    let mixed: ShownUnbounded<u32, NoDebug> = ShownUnbounded::Mixed {
        shown: 2,
        hidden: NoDebug,
    };
    assert_eq!(
        format!("{mixed:?}"),
        format!("{tn}::Mixed {{ shown: 2, hidden: \"***\" }}")
    );

    let s = ShownUnboundedStruct {
        shown: 3u32,
        hidden: NoDebug,
    };
    assert_opaque(&s);
    let tn = type_name::<ShownUnboundedStruct<u32, NoDebug>>();
    assert_eq!(
        format!("{s:?}"),
        format!("{tn} {{ shown: 3, hidden: \"***\" }}")
    );
}

// Field names that match locals the derive uses internally (the formatter `f`
// and the type-name binding `tn`) must not shadow them.
#[derive(OpaqueDebug)]
enum Collides {
    Named {
        f: u8,
        #[non_sensitive]
        tn: u8,
    },
    #[non_sensitive]
    Shown { f: u8 },
}

#[derive(OpaqueDebug)]
struct CollidesStruct {
    f: u8,
    #[non_sensitive]
    tn: u8,
}

#[test]
fn enum_field_named_like_derive_locals_does_not_shadow_them() {
    let tn = type_name::<Collides>();

    let named = Collides::Named { f: 1, tn: 2 };
    assert_opaque(&named);
    assert_eq!(
        format!("{named:?}"),
        format!("{tn}::Named {{ f: \"***\", tn: 2 }}")
    );

    let shown = Collides::Shown { f: 3 };
    assert_eq!(format!("{shown:?}"), format!("{tn}::Shown {{ f: 3 }}"));
}

#[test]
fn struct_field_named_like_derive_locals_does_not_shadow_them() {
    let tn = type_name::<CollidesStruct>();
    let s = CollidesStruct { f: 1, tn: 2 };
    assert_opaque(&s);
    assert_eq!(format!("{s:?}"), format!("{tn} {{ f: \"***\", tn: 2 }}"));
}

// The impls carry the input's generics, so a lowercase const parameter named
// like a derive local (`f`, `tn`) is in scope inside `fmt` and must not
// collide with it.
#[derive(OpaqueDebug)]
enum ConstNamedF<'a, const f: usize> {
    Borrowed(&'a [u8; f]),
    Named {
        bytes: [u8; f],
        #[non_sensitive]
        len: usize,
    },
    Empty,
}

#[derive(OpaqueDebug)]
struct ConstNamedTn<const tn: usize> {
    bytes: [u8; tn],
    #[non_sensitive]
    len: usize,
}

#[derive(OpaqueDebug)]
struct ConstNamedTupleDt<const dt: usize>([u8; dt]);

#[test]
fn enum_const_param_named_like_derive_local() {
    let tn = type_name::<ConstNamedF<'static, 2>>();
    let bytes = [1u8, 2];

    // Type ascription, not a turbofish on the variant: rustc 1.96 rejects a
    // lifetime argument there (E0109).
    let borrowed: ConstNamedF<'_, 2> = ConstNamedF::Borrowed(&bytes);
    assert_opaque(&borrowed);
    assert_eq!(format!("{borrowed:?}"), format!("{tn}::Borrowed(\"***\")"));

    let named: ConstNamedF<'_, 2> = ConstNamedF::Named { bytes, len: 2 };
    assert_eq!(
        format!("{named:?}"),
        format!("{tn}::Named {{ bytes: \"***\", len: 2 }}")
    );

    let empty: ConstNamedF<'_, 2> = ConstNamedF::Empty;
    assert_eq!(format!("{empty:?}"), format!("{tn}::Empty"));
}

#[test]
fn struct_const_param_named_like_derive_local() {
    let tn = type_name::<ConstNamedTn<3>>();
    let s = ConstNamedTn::<3> {
        bytes: [1, 2, 3],
        len: 3,
    };
    assert_opaque(&s);
    assert_eq!(
        format!("{s:?}"),
        format!("{tn} {{ bytes: \"***\", len: 3 }}")
    );

    let tn = type_name::<ConstNamedTupleDt<3>>();
    let t = ConstNamedTupleDt::<3>([1, 2, 3]);
    assert_opaque(&t);
    assert_eq!(format!("{t:?}"), format!("{tn}(\"***\")"));
}

// An empty enum has no values to format, but the derive must still expand:
// `match self {}` on `&Never` is not exhaustive (E0004).
#[derive(OpaqueDebug)]
enum Never {}

#[test]
fn empty_enum_derives() {
    assert_opaque_impl::<Never>();
}

// Raw identifiers print without their `r#`, as `#[derive(Debug)]` does.
#[derive(OpaqueDebug)]
struct RawStruct {
    r#type: u8,
    #[non_sensitive]
    r#match: u8,
}

#[derive(OpaqueDebug)]
enum RawEnum {
    V {
        r#type: u8,
        #[non_sensitive]
        r#match: u8,
    },
}

#[test]
fn raw_identifier_fields_print_unraw() {
    let tn = type_name::<RawStruct>();
    let s = RawStruct {
        r#type: 1,
        r#match: 2,
    };
    assert_eq!(
        format!("{s:?}"),
        format!("{tn} {{ type: \"***\", match: 2 }}")
    );

    let tn = type_name::<RawEnum>();
    let e = RawEnum::V {
        r#type: 1,
        r#match: 2,
    };
    assert_eq!(
        format!("{e:?}"),
        format!("{tn}::V {{ type: \"***\", match: 2 }}")
    );
}

// The derive must not pick up same-named macros at the call site.
mod call_site_hygiene {
    // The marker trait must be in scope (see the note in the derive). The
    // derive itself is still named by full path below.
    use vitaminc_protected::OpaqueDebug;

    // Unused on purpose: the derive must not expand to it.
    #[allow(unused_macros)]
    macro_rules! write {
        ($($t:tt)*) => {
            compile_error!("user write! was picked up by the derive")
        };
    }

    // Unused on purpose: the derive must not expand to it.
    #[allow(unused_macros)]
    macro_rules! concat {
        ($($t:tt)*) => {
            compile_error!("user concat! was picked up by the derive")
        };
    }

    #[derive(vitaminc_protected::OpaqueDebug)]
    pub enum E {
        V {
            a: u8,
            #[non_sensitive]
            b: u8,
        },
        T(u8),
        U,
    }

    #[derive(vitaminc_protected::OpaqueDebug)]
    pub struct S {
        pub a: u8,
    }
}

#[test]
fn derive_ignores_call_site_macros() {
    use call_site_hygiene::{E, S};

    let tn = type_name::<E>();
    let v = E::V { a: 1, b: 2 };
    assert_opaque(&v);
    assert_eq!(format!("{v:?}"), format!("{tn}::V {{ a: \"***\", b: 2 }}"));
    assert_eq!(format!("{:?}", E::T(3)), format!("{tn}::T(\"***\")"));
    assert_eq!(format!("{:?}", E::U), format!("{tn}::U"));

    let s = S { a: 1 };
    assert_opaque(&s);
    let tn = type_name::<S>();
    assert_eq!(format!("{s:?}"), format!("{tn} {{ a: \"***\" }}"));
}
