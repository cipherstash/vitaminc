// F2: the impls carry the input's generics, so a const parameter named like
// the derive's `other` parameter or a field binding is in scope inside `ts_eq`
// and must not collide with it.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq)]
struct Key<const __ts_other: usize, const __ts_lhs_0: usize> {
    bytes: [u8; __ts_other],
    tag: [u8; __ts_lhs_0],
}

#[derive(TimingSafeEq)]
enum E<const __ts_other: usize, const __ts_rhs_0: usize> {
    Tuple([u8; __ts_other]),
    Named { bytes: [u8; __ts_rhs_0] },
}

fn main() {
    let k = Key::<2, 1> {
        bytes: [1, 2],
        tag: [3],
    };
    assert!(k == Key { bytes: [1, 2], tag: [3] });
    assert!(k != Key { bytes: [1, 2], tag: [4] });
    assert!(E::<2, 1>::Tuple([1, 2]) == E::Tuple([1, 2]));
    assert!(E::<2, 1>::Named { bytes: [1] } != E::Named { bytes: [2] });
}
