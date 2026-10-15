// F2: the impls carry the input's generics, so a const parameter named like
// the derive's accumulator local is in scope inside `ts_eq` and must not
// collide with the `let mut` binding.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq)]
struct Key<const __ts_acc: usize>([u8; __ts_acc]);

fn main() {
    assert!(Key::<2>([1, 2]) == Key([1, 2]));
    assert!(Key::<2>([1, 2]) != Key([1, 3]));
}
