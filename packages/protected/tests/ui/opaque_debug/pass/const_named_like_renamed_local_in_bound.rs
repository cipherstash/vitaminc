// F3: a const parameter `__f_value` makes the derive rename the binding for
// field `value` to `__f_value_1`. A constant in scope with that suffixed name,
// used in a shown field type, must still resolve to the constant in the
// generated `Debug` bound.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::OpaqueDebug;

const __f_value_1: usize = 2;

#[derive(OpaqueDebug)]
enum E<T, const __f_value: usize> {
    Named {
        #[non_sensitive]
        value: [T; __f_value_1],
    },
}

fn main() {
    let tn = core::any::type_name::<E<u8, 1>>();
    assert_eq!(
        format!("{:?}", E::<u8, 1>::Named { value: [1, 2] }),
        format!("{tn}::Named {{ value: [1, 2] }}")
    );
}
