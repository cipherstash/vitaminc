// The derive emits no `#[allow]`, which a caller's `#![forbid(...)]` would
// reject, and binds fields by position, so uppercase field names (allowed on
// the type) do not give generated locals that trip `non_snake_case`.
#![forbid(dead_code)]
#![deny(non_snake_case)]

use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
struct Tuple([u8; 2]);

#[derive(OpaqueDebug)]
#[allow(non_snake_case)]
struct Named {
    Key: u8,
}

#[derive(OpaqueDebug)]
#[allow(non_snake_case)]
enum E {
    Named { Key: u8 },
    Tuple(u8),
}

fn main() {
    let (t, n) = (Tuple([1, 2]), Named { Key: 1 });
    let _ = format!("{t:?} {n:?}");
    // `dead_code` ignores derived `Debug` impls, so read the fields here.
    let _ = (t.0, n.Key);
    for e in [E::Named { Key: 1 }, E::Tuple(2)] {
        let _ = format!("{e:?}");
        match e {
            E::Named { Key: k } | E::Tuple(k) => drop(k),
        }
    }
}
