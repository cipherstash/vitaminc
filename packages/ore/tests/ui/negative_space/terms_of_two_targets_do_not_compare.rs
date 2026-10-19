// A term under a marker is labelled with it, so two targets' terms cannot
// meet in one comparison: the answer would be noise.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{I32, I64};
use vitaminc_ore::OrderEncrypt;

fn main() {
    let (i32s, i64s) = (clear::Clear.target(I32), clear::Clear.target(I64));
    let (a, b) = (i32s.encrypt(1i32).unwrap(), i64s.encrypt(1i32).unwrap());
    let _ = i32s.compare(&a, &b);
}
