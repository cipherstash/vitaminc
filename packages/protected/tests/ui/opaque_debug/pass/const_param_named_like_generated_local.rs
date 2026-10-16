// The impls carry the input's generics, so a const parameter that shares a
// name with a derive-generated local (the formatter or an enum field binding)
// is in scope inside `fmt` and must not capture that local.
#![allow(non_upper_case_globals, dead_code)]

use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
struct Formatter<const __opaque_debug_f: usize>(#[non_sensitive] u8);

#[derive(OpaqueDebug)]
enum Bindings<const __f0: usize, const __f1: usize> {
    Tuple(#[non_sensitive] u8),
    Named {
        #[non_sensitive]
        value: u8,
        #[non_sensitive]
        other: u8,
    },
}

fn main() {
    let tn = core::any::type_name::<Formatter<1>>();
    assert_eq!(format!("{:?}", Formatter::<1>(1)), format!("{tn}(1)"));
    let tn = core::any::type_name::<Bindings<1, 2>>();
    assert_eq!(
        format!("{:?}", Bindings::<1, 2>::Tuple(2)),
        format!("{tn}::Tuple(2)")
    );
    assert_eq!(
        format!("{:?}", Bindings::<1, 2>::Named { value: 3, other: 4 }),
        format!("{tn}::Named {{ value: 3, other: 4 }}")
    );
}
