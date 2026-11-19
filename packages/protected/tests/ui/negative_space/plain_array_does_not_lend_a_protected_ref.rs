// A `ProtectedRef` comes from a protected source. A plain `[u8; N]` is not
// one: nothing wipes it, so lending it directly would make the unwiped path
// the easy path. A key held that way goes into a `Protected` first, and
// that owner lends.
use vitaminc_protected::{AsProtectedRef, ProtectedRef};

fn read(key: ProtectedRef<'_, [u8; 32]>) -> usize {
    key.risky_ref().len()
}

fn main() {
    let key = [0u8; 32];
    read(key.as_protected_ref());
}
