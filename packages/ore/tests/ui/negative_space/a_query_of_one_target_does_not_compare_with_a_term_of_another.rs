// A query under a marker is labelled with it, as a term is, so a query of
// one target cannot meet a term of another in one comparison.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{I32, I64};
use vitaminc_ore::OrderEncrypt;

fn main() {
    let (i32s, i64s) = (clear::Clear.target(I32), clear::Clear.target(I64));
    let (query, term) = (i32s.encrypt_query(1i32).unwrap(), i64s.encrypt(1i32).unwrap());
    let _ = i32s.compare_query(&query, &term);
}
