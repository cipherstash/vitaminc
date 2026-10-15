// F1: the derive emits `ShownFieldTy: Debug` bounds on the `Debug` impl. A
// constant in scope that shares a name with a derive-generated local and is
// used in such a field type must still resolve to that constant in the bound,
// not to anything the derive declares.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::OpaqueDebug;

const __f_value: usize = 2;

#[derive(OpaqueDebug)]
enum E<T> {
    Named {
        #[non_sensitive]
        value: [T; __f_value],
    },
}

fn main() {
    let tn = core::any::type_name::<E<u8>>();
    assert_eq!(
        format!("{:?}", E::<u8>::Named { value: [1, 2] }),
        format!("{tn}::Named {{ value: [1, 2] }}")
    );
}
