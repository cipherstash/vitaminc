// A `ProtectedRef` comes from a protected source. A plain `Vec<u8>` or
// `&[u8]` is not one: nothing wipes it, so lending it directly would make
// the unwiped path the easy path. Bytes held that way go into a `Protected`
// or a `Buffer` first, and that owner lends.
use vitaminc_protected::{AsProtectedRef, ProtectedRef};

fn read(bytes: ProtectedRef<'_, [u8]>) -> usize {
    bytes.risky_ref().len()
}

fn main() {
    let owned: Vec<u8> = vec![0u8; 32];
    read(owned.as_protected_ref());

    let borrowed: &[u8] = &[0u8; 32];
    read(borrowed.as_protected_ref());
}
