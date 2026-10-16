// F2: a unit struct in scope named like the derive's `other` parameter must
// not turn that parameter into a pattern against the struct.
#![allow(non_camel_case_types, dead_code)]

use vitaminc_protected::TimingSafeEq;

struct __ts_other;

#[derive(TimingSafeEq)]
struct Key([u8; 2]);

fn main() {
    assert!(Key([1, 2]) == Key([1, 2]));
    assert!(Key([1, 2]) != Key([1, 3]));
}
