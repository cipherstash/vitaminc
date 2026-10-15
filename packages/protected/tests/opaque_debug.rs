//! `#[derive(OpaqueDebug)]` on generic types.
//!
//! The derive must carry the type's lifetimes, type parameters, const
//! parameters and where clause onto both impls it emits. A type that fails to
//! compile here is the regression: these tests mostly prove that the derive
//! expands at all, then pin the masked output shape.

// Masked struct fields are never read: the derived `Debug` writes the mask in
// their place, which is the point.
#![allow(dead_code)]
// The lowercase const parameters below are deliberate. The lint fires again on
// the derived impls, which copy the parameters and sit outside any item-level
// `#[allow]`, so it is silenced for the whole file.
#![allow(non_upper_case_globals)]

use core::any::type_name;
use core::fmt::Debug;
use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
enum Physical<'a> {
    Text(&'a str),
    Pair { left: &'a str, right: &'a str },
    Null,
}

#[derive(OpaqueDebug)]
enum Labelled<T>
where
    T: Clone + Debug,
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

fn assert_opaque<T: OpaqueDebug + Debug>(_: &T) {}

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
        format!("{tn}::Pair {{left: \"***\", right: \"***\"}}")
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
        format!("{tn}::Named {{hidden: \"***\", shown: 2}}")
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
        format!("{tn}::Named {{f: \"***\", tn: 2}}")
    );

    let shown = Collides::Shown { f: 3 };
    assert_eq!(format!("{shown:?}"), format!("{tn}::Shown {{f: 3}}"));
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

    let borrowed = ConstNamedF::<'_, 2>::Borrowed(&bytes);
    assert_opaque(&borrowed);
    assert_eq!(format!("{borrowed:?}"), format!("{tn}::Borrowed(\"***\")"));

    let named = ConstNamedF::<'_, 2>::Named { bytes, len: 2 };
    assert_eq!(
        format!("{named:?}"),
        format!("{tn}::Named {{bytes: \"***\", len: 2}}")
    );

    let empty = ConstNamedF::<'_, 2>::Empty;
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
