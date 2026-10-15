//! `#[derive(OpaqueDebug)]` on generic types.
//!
//! The derive must carry the type's lifetimes, type parameters, const
//! parameters and where clause onto both impls it emits. A type that fails to
//! compile here is the regression: these tests mostly prove that the derive
//! expands at all, then pin the masked output shape.

// Masked struct fields are never read: the derived `Debug` writes the mask in
// their place, which is the point.
#![allow(dead_code)]

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
