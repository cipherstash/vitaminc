// A query has its own type, so it cannot be stored or compared where a
// term is expected, nor a term where a query is.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::I32;
use vitaminc_ore::OrderEncrypt;

fn main() {
    let i32s = clear::Clear.target(I32);
    let (query, term) = (i32s.encrypt_query(1i32).unwrap(), i32s.encrypt(1i32).unwrap());
    let _ = i32s.compare(&query, &term);
    let _ = i32s.compare_query(&term, &term);
}
