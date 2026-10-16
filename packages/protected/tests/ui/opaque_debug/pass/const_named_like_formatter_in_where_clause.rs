// F1: the input's where clause is copied onto both impls. A constant in scope
// named like the derive's formatter and used in that where clause must still
// resolve to the constant there.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::OpaqueDebug;

const __opaque_debug_f: usize = 3;

#[derive(OpaqueDebug)]
struct S<T>
where
    [T; __opaque_debug_f]: Sized,
{
    #[non_sensitive]
    x: T,
}

fn main() {
    let tn = core::any::type_name::<S<u8>>();
    assert_eq!(format!("{:?}", S { x: 1u8 }), format!("{tn} {{ x: 1 }}"));
}
