// F2: the derive binds each field as `__ts_lhs_<index>` and `__ts_rhs_<index>`.
// A constant or tuple struct in scope with one of those names must not turn a
// binding into a pattern against that item, in a struct or an enum arm.
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use vitaminc_protected::TimingSafeEq;

const __ts_lhs_0: u8 = 0;

struct __ts_rhs_1(u8);

#[derive(TimingSafeEq)]
struct Named {
    a: u8,
    b: u8,
}

#[derive(TimingSafeEq)]
struct Tuple(u8, u8);

#[derive(TimingSafeEq)]
enum E {
    Named { a: u8, b: u8 },
    Tuple(u8, u8),
}

fn main() {
    assert!(Named { a: 1, b: 2 } == Named { a: 1, b: 2 });
    assert!(Named { a: 1, b: 2 } != Named { a: 1, b: 3 });
    assert!(Tuple(1, 2) == Tuple(1, 2));
    assert!(Tuple(1, 2) != Tuple(2, 2));
    assert!(E::Named { a: 1, b: 2 } == E::Named { a: 1, b: 2 });
    assert!(E::Named { a: 1, b: 2 } != E::Named { a: 1, b: 3 });
    assert!(E::Tuple(1, 2) == E::Tuple(1, 2));
    assert!(E::Tuple(1, 2) != E::Tuple(1, 3));
    assert!(E::Tuple(1, 2) != E::Named { a: 1, b: 2 });
}
