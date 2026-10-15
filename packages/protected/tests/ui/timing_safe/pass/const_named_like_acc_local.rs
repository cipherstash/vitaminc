// F2: a constant in scope named like the derive's accumulator local must not
// collide with the `let mut` binding.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::TimingSafeEq;

const __ts_acc: u8 = 0;

#[derive(TimingSafeEq)]
struct Key([u8; 2]);

fn main() {
    assert!(Key([1, 2]) == Key([1, 2]));
    assert!(Key([1, 2]) != Key([1, 3]));
}
