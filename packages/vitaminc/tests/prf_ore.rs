//! Checks that the facade's `prf` feature turns on `vitaminc-ore/prf` when
//! the `ore` feature is also on. A workspace build turns on
//! `vitaminc-ore/prf` anyway, through the dev-dependencies of
//! `vitaminc-ore`. So CI runs this test on the facade alone, where only the
//! facade's features can turn it on.

use vitaminc::ore::SchemeVisitor;

#[test]
fn the_facade_forwards_prf_to_ore() {
    assert_eq!(
        format!("{:?}", SchemeVisitor::<()>::new()),
        "SchemeVisitor",
        "the facade reaches the ore crate's SchemeVisitor"
    );
}
