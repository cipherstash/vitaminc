//! `#[derive(TimingSafeEq)]` on a borrowed, float-bearing enum shaped like a
//! plaintext value (unit, `bool`, `f64`, `&str`, `&[u8]` variants).

use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq, Debug)]
enum Physical<'a> {
    Null,
    Bool(bool),
    Float(f64),
    Text(&'a str),
    Bytes(&'a [u8]),
}

fn eq(a: &Physical<'_>, b: &Physical<'_>) -> bool {
    bool::from(a.ts_eq(b))
}

#[test]
fn same_variant_equal_values_are_equal() {
    let bytes = [1u8, 2, 3];
    let cases = [
        (Physical::Null, Physical::Null),
        (Physical::Bool(true), Physical::Bool(true)),
        (Physical::Float(1.5), Physical::Float(1.5)),
        (Physical::Float(f64::NAN), Physical::Float(f64::NAN)),
        (Physical::Text("abc"), Physical::Text("abc")),
        (Physical::Bytes(&bytes), Physical::Bytes(&[1, 2, 3])),
    ];
    for (a, b) in &cases {
        assert!(eq(a, b), "{a:?} should equal {b:?}");
        assert_eq!(a, b);
    }
}

#[test]
fn same_variant_different_values_are_unequal() {
    let cases = [
        (Physical::Bool(true), Physical::Bool(false)),
        (Physical::Float(1.5), Physical::Float(2.5)),
        (Physical::Float(-0.0), Physical::Float(0.0)),
        (Physical::Text("abc"), Physical::Text("abd")),
        (Physical::Bytes(&[1, 2, 3]), Physical::Bytes(&[1, 2, 4])),
        // Slices of different lengths.
        (Physical::Bytes(&[1, 2, 3]), Physical::Bytes(&[1, 2])),
        (Physical::Bytes(&[]), Physical::Bytes(&[0])),
    ];
    for (a, b) in &cases {
        assert!(!eq(a, b), "{a:?} should not equal {b:?}");
        assert_ne!(a, b);
    }
}

#[test]
fn different_variants_are_unequal() {
    let values = [
        Physical::Null,
        Physical::Bool(false),
        Physical::Float(0.0),
        Physical::Text(""),
        Physical::Bytes(&[]),
    ];
    for (i, a) in values.iter().enumerate() {
        for (j, b) in values.iter().enumerate() {
            assert_eq!(eq(a, b), i == j, "{a:?} vs {b:?}");
        }
    }
}
