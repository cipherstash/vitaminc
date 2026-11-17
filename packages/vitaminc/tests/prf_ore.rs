//! The facade's `prf` feature turns on `vitaminc-ore/prf` when `ore` is on
//! too. The workspace build turns that feature on anyway (through
//! `vitaminc-ore`'s dev-dependencies), so CI runs this test on the facade
//! alone.

use vitaminc::ore::SchemeVisitor;

#[test]
fn the_facade_forwards_prf_to_ore() {
    assert_eq!(
        format!("{:?}", SchemeVisitor::<()>::new()),
        "SchemeVisitor",
        "the facade reaches the ore crate's SchemeVisitor"
    );
}
