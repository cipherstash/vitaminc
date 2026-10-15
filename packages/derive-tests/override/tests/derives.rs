//! `#[derive(OpaqueDebug)]` and `#[derive(TimingSafeEq)]` from a crate that
//! depends only on `vitaminc` and reaches the protected crate through its own re-export, named with `crate = "crate::deps::p"`.
//!
//! Nothing is imported: the derives are named by full path and every item
//! they emit must resolve on its own.

#![allow(dead_code)]

/// The protected crate under a path the derives cannot discover on their own.
mod deps {
    pub use vitaminc::protected as p;
}

#[derive(vitaminc::protected::OpaqueDebug)]
#[opaque_debug(crate = "crate::deps::p")]
enum Secret {
    Tuple(u8),
    Named {
        hidden: u8,
        #[non_sensitive]
        shown: u8,
    },
    Unit,
}

#[derive(vitaminc::protected::OpaqueDebug)]
#[opaque_debug(crate = "crate::deps::p")]
struct Token {
    value: [u8; 4],
}

#[derive(vitaminc::protected::TimingSafeEq)]
#[timing_safe(crate = "crate::deps::p")]
struct Key([u8; 4]);

#[derive(vitaminc::protected::TimingSafeEq)]
#[timing_safe(crate = "crate::deps::p")]
enum Kind {
    A(u8),
    B { x: u8 },
    C,
}

fn assert_opaque<T: crate::deps::p::OpaqueDebug + ::core::fmt::Debug>(_: &T) {}

fn ts_eq<T: crate::deps::p::TimingSafeEq>(a: &T, b: &T) -> bool {
    crate::deps::p::TimingSafeEq::ts_eq(a, b).into()
}

#[test]
fn opaque_debug_masks_fields() {
    let tn = ::core::any::type_name::<Secret>();
    let tuple = Secret::Tuple(1);
    assert_opaque(&tuple);
    assert_eq!(format!("{tuple:?}"), format!("{tn}::Tuple(\"***\")"));
    assert_eq!(
        format!(
            "{:?}",
            Secret::Named {
                hidden: 1,
                shown: 2
            }
        ),
        format!("{tn}::Named {{ hidden: \"***\", shown: 2 }}")
    );
    assert_eq!(format!("{:?}", Secret::Unit), format!("{tn}::Unit"));

    let token = Token {
        value: [1, 2, 3, 4],
    };
    assert_opaque(&token);
    let tn = ::core::any::type_name::<Token>();
    assert_eq!(format!("{token:?}"), format!("{tn} {{ value: \"***\" }}"));
}

#[test]
fn timing_safe_eq_compares_fields() {
    assert!(ts_eq(&Key([1, 2, 3, 4]), &Key([1, 2, 3, 4])));
    assert!(!ts_eq(&Key([1, 2, 3, 4]), &Key([1, 2, 3, 5])));
    assert!(Key([1, 2, 3, 4]) == Key([1, 2, 3, 4]));

    assert!(ts_eq(&Kind::A(1), &Kind::A(1)));
    assert!(!ts_eq(&Kind::B { x: 1 }, &Kind::B { x: 2 }));
    assert!(!ts_eq(&Kind::C, &Kind::A(1)));
    assert!(Kind::C == Kind::C);
}
