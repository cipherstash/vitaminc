//! `#[derive(TimingSafeEq)]` hygiene.
//!
//! The impls carry the input's generics and expand in the caller's module, so
//! a lowercase const parameter named like one of the derive's locals or
//! parameters (`acc`, `other`) must not collide with it, and the derive must
//! work by full path with nothing imported.

// The lowercase const parameters below are deliberate. The lint also fires on
// the derived impls, which copy the parameters and sit outside any item-level
// `#[allow]`, so it is allowed for the whole file.
#![allow(non_upper_case_globals)]

use vitaminc_protected::TimingSafeEq;

#[derive(vitaminc_protected::TimingSafeEq)]
struct ConstAcc<const acc: usize>([u8; acc]);

#[derive(vitaminc_protected::TimingSafeEq)]
struct ConstOther<const other: usize> {
    bytes: [u8; other],
}

#[derive(vitaminc_protected::TimingSafeEq)]
enum ConstAccEnum<const acc: usize, const other: usize> {
    Tuple([u8; acc]),
    Named { bytes: [u8; other] },
    Unit,
}

#[test]
fn const_param_named_acc_does_not_collide() {
    let a = ConstAcc::<2>([1, 2]);
    assert!(bool::from(a.ts_eq(&ConstAcc([1, 2]))));
    assert!(!bool::from(a.ts_eq(&ConstAcc([1, 3]))));
    assert!(a == ConstAcc([1, 2]));
    assert!(a != ConstAcc([2, 2]));
}

#[test]
fn const_param_named_other_does_not_collide() {
    let a = ConstOther::<2> { bytes: [1, 2] };
    assert!(bool::from(a.ts_eq(&ConstOther { bytes: [1, 2] })));
    assert!(a == ConstOther { bytes: [1, 2] });
    assert!(a != ConstOther { bytes: [1, 3] });
}

#[test]
fn enum_const_params_named_like_derive_locals() {
    type E = ConstAccEnum<2, 3>;
    assert!(E::Tuple([1, 2]) == E::Tuple([1, 2]));
    assert!(E::Tuple([1, 2]) != E::Tuple([1, 3]));
    assert!(E::Named { bytes: [1, 2, 3] } == E::Named { bytes: [1, 2, 3] });
    assert!(E::Named { bytes: [1, 2, 3] } != E::Named { bytes: [1, 2, 4] });
    assert!(E::Unit == E::Unit);
    assert!(E::Unit != E::Tuple([1, 2]));
}

// No `use` of the trait in this module: the derive must name it by path.
mod no_import {
    #[derive(vitaminc_protected::TimingSafeEq)]
    pub struct Key(pub [u8; 4]);

    #[derive(vitaminc_protected::TimingSafeEq)]
    pub enum Kind {
        A(u8),
        B,
    }
}

#[test]
fn derive_by_full_path_needs_no_import() {
    use no_import::{Key, Kind};

    assert!(Key([1, 2, 3, 4]) == Key([1, 2, 3, 4]));
    assert!(Key([1, 2, 3, 4]) != Key([1, 2, 3, 5]));
    assert!(bool::from(Key([0; 4]).ts_eq(&Key([0; 4]))));
    assert!(Kind::A(1) == Kind::A(1));
    assert!(Kind::A(1) != Kind::B);
}

// `crate = "..."` overrides the resolved path to the protected crate.
mod crate_override {
    #[derive(vitaminc_protected::TimingSafeEq)]
    #[timing_safe(crate = "::vitaminc_protected")]
    pub struct Overridden(pub [u8; 2]);
}

#[test]
fn crate_override_is_used_as_the_root() {
    use crate_override::Overridden;
    assert!(Overridden([1, 2]) == Overridden([1, 2]));
    assert!(Overridden([1, 2]) != Overridden([2, 1]));
}
