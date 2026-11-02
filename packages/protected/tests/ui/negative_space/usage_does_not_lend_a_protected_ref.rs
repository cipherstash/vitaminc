// A `Usage` scope says which code may take the value. A `ProtectedRef` would
// carry it to any consumer (`zip_ref`, `update_with_ref`, encryption), so a
// `Usage` does not lend one; `risky_ref` is the deliberate way in.
use vitaminc_protected::{AsProtectedRef, Protected, ProtectedRef, Usage};

fn main() {
    let key: Usage<Protected<[u8; 32]>> = Usage::new([0u8; 32]);
    let _: ProtectedRef<'_, [u8; 32]> = key.as_protected_ref();
}
