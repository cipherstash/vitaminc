// The null policy of a marker target is part of the space's type, so a
// term of a nulls-first space does not compile against a nulls-last
// space's comparison, and nor does it meet a nulls-last query.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{First, Last, I32};
use vitaminc_ore::OrderEncrypt;

fn main() {
    let plain = clear::Clear.target(I32);
    let (first, last) = (plain.nulls(First), plain.nulls(Last));
    let (a, b) = (first.encrypt_checked(1i32).unwrap(), last.encrypt_checked(1i32).unwrap());
    let _ = last.compare(&a, &b);
    let query = last.null_query().unwrap();
    let _ = last.compare_query(&query, &a);
}
