//! The facade's `normalize` feature turns on `vitaminc-prf/normalize` when
//! `prf` is on too. The workspace build turns that feature on anyway
//! (through `vitaminc-hmac`'s dev-dependencies), so CI runs this test on
//! the facade alone.

use vitaminc::normalize::Normalized;
use vitaminc::prf::{EqualityTerm, PrfValue};

fn assert_prf_value<T: PrfValue>() {}

#[test]
fn the_facade_forwards_normalize_to_prf() {
    assert_prf_value::<Normalized>();
    assert_prf_value::<&Normalized>();
    assert_prf_value::<EqualityTerm<'static>>();
}
