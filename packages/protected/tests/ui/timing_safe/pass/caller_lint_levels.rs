// The derive emits no `#[allow]`, which a caller's `#![forbid(...)]` would
// reject, and binds fields by position, so uppercase field names (allowed on
// the type) do not give generated locals that trip `non_snake_case`.
#![forbid(dead_code)]
#![deny(non_snake_case)]

use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq)]
struct Tuple([u8; 2]);

#[derive(TimingSafeEq)]
#[allow(non_snake_case)]
struct Named {
    Key: u8,
}

#[derive(TimingSafeEq)]
#[allow(non_snake_case)]
enum E {
    Named { Key: u8 },
    Tuple(u8),
}

fn main() {
    assert!(Tuple([1, 2]) == Tuple([1, 2]));
    assert!(Named { Key: 1 } != Named { Key: 2 });
    assert!(E::Named { Key: 1 } == E::Named { Key: 1 });
    assert!(E::Tuple(1) != E::Named { Key: 1 });
}
