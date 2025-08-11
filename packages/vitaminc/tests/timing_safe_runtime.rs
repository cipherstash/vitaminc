#![allow(dead_code)]
use vitaminc::protected::{OpaqueDebug, TimingSafeEq};

#[test]
fn struct_named_fields_anded() {
    #[derive(TimingSafeEq, Debug)]
    struct Pair {
        a: u8,
        b: u8,
    }

    let x = Pair { a: 1, b: 2 };
    let y = Pair { a: 1, b: 2 };
    let z = Pair { a: 1, b: 3 };

    // Equal
    assert_eq!(x, y);
    assert_eq!(x.ts_eq(&y).unwrap_u8(), 1);

    // One field differs -> AND collapses to 0
    assert!(x != z);
    assert_eq!(x.ts_eq(&z).unwrap_u8(), 0);
}

#[test]
fn struct_tuple_fields_anded() {
    #[derive(TimingSafeEq, Debug)]
    struct Triple(u8, u8, u8);

    let a = Triple(9, 8, 7);
    let b = Triple(9, 8, 7);
    let c = Triple(9, 0, 7);

    assert_eq!(a, b);
    assert!(bool::from(a.ts_eq(&b)));

    assert_ne!(a, c);
    assert!(!bool::from(a.ts_eq(&c)));
}

#[test]
fn struct_unit_is_always_equal() {
    #[derive(TimingSafeEq, Debug)]
    struct Marker;

    let m1 = Marker;
    let m2 = Marker;
    assert_eq!(m1, m2);
    assert!(bool::from(m1.ts_eq(&m2)));
}

#[test]
fn enum_variants_match_and_fields_anded() {
    #[derive(TimingSafeEq, Debug)]
    enum E {
        Unit,
        Tup(u8, u8),
        Rec { x: u8, y: u8 },
    }

    let a = E::Unit;
    let b = E::Unit;
    assert!(a == b);
    assert_eq!(a.ts_eq(&b).unwrap_u8(), 1);

    let t1 = E::Tup(1, 2);
    let t2 = E::Tup(1, 2);
    let t3 = E::Tup(1, 3);

    assert_eq!(t1, t2);
    assert!(bool::from(t1.ts_eq(&t2)));
    assert_ne!(t1, t3);
    assert!(!bool::from(t1.ts_eq(&t3)));

    let r1 = E::Rec { x: 5, y: 6 };
    let r2 = E::Rec { x: 5, y: 6 };
    let r3 = E::Rec { x: 5, y: 7 };

    assert_eq!(r1, r2);
    assert!(bool::from(r1.ts_eq(&r2)));
    assert_ne!(r1, r3);
    assert!(!bool::from(r1.ts_eq(&r3)));

    // Different variants are never equal
    assert_ne!(a, t1);
    assert!(!bool::from(a.ts_eq(&t1)));
    assert_ne!(t1, r1);
    assert!(!bool::from(t1.ts_eq(&r1)));
}

#[test]
fn generics_and_const_generics_preserved() {
    #[derive(TimingSafeEq, OpaqueDebug)]
    struct Wrap<T>(T);

    #[derive(TimingSafeEq, OpaqueDebug, Clone, Copy)]
    struct Key<const N: usize>([u8; N]);

    let k1 = Key::<3>([1, 2, 3]);
    let k2 = Key::<3>([1, 2, 3]);
    let k3 = Key::<3>([1, 2, 9]);

    let w1 = Wrap(k1);
    let w2 = Wrap(k2);
    let w3 = Wrap(k3);

    assert_eq!(k1, k2);
    assert!(bool::from(w1.ts_eq(&w2)));

    assert_ne!(w1, w3);
    assert!(!bool::from(w1.ts_eq(&w3)));
}

#[test]
fn partialeq_routes_through_ts_eq() {
    #[derive(TimingSafeEq, Debug)]
    struct Demo(u8);

    let a = Demo(7);
    let b = Demo(7);
    let c = Demo(8);

    // eq uses ts_eq internally
    assert_eq!(a, b);
    assert!(bool::from(a.ts_eq(&b)));

    assert_ne!(a, c);
    assert!(!bool::from(a.ts_eq(&c)));
}

#[test]
fn eq_is_implemented() {
    #[derive(TimingSafeEq)]
    struct Demo(u8);
    // If this compiles, `Eq` is implemented. Check reflexivity/symmetry quickly.
    let a = Demo(1);
    let b = Demo(1);
    let c = Demo(2);

    // reflexive
    assert!(a == a);

    // associative
    assert!(a == b);
    assert!(b == a);

    // distinguish
    assert!(a != c);
}
