// Items in scope that share a name with a derive-generated local (the
// formatter or an enum field binding) must not capture that local: a `fn`
// parameter or `ref` binding with the same name as a unit struct, tuple struct
// or constant in scope resolves as a pattern against that item.
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
struct __opaque_debug_f;

#[derive(OpaqueDebug)]
struct __f0(u8);

const __f1: u8 = 0;

#[derive(OpaqueDebug)]
struct Probe {
    #[non_sensitive]
    value: u8,
}

#[derive(OpaqueDebug)]
enum ProbeEnum {
    Tuple(#[non_sensitive] u8),
    Named {
        #[non_sensitive]
        value: u8,
        #[non_sensitive]
        other: u8,
    },
}

fn main() {
    let tn = core::any::type_name::<Probe>();
    assert_eq!(
        format!("{:?}", Probe { value: 1 }),
        format!("{tn} {{ value: 1 }}")
    );
    let tn = core::any::type_name::<ProbeEnum>();
    assert_eq!(
        format!("{:?}", ProbeEnum::Tuple(2)),
        format!("{tn}::Tuple(2)")
    );
    assert_eq!(
        format!("{:?}", ProbeEnum::Named { value: 3, other: 4 }),
        format!("{tn}::Named {{ value: 3, other: 4 }}")
    );
}
