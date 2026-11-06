// A `ProtectedRef` comes from a protected source. A plain `str` or
// `Cow<str>` is not one: nothing wipes it, so lending it directly, as text
// or as bytes, would make the unwiped path the easy path. Text held that
// way goes into a `Protected<String>` first, and that owner lends a borrow
// that `as_deref` narrows to `str`.
use std::borrow::Cow;
use vitaminc_protected::{AsProtectedRef, ProtectedRef};

fn read_text(text: ProtectedRef<'_, str>) -> usize {
    text.risky_ref().len()
}

fn read_bytes(bytes: ProtectedRef<'_, [u8]>) -> usize {
    bytes.risky_ref().len()
}

fn main() {
    read_text("pw".as_protected_ref());
    read_bytes("pw".as_protected_ref());

    let cow: Cow<'_, str> = Cow::Borrowed("pw");
    read_text(cow.as_protected_ref());
    read_bytes(cow.as_protected_ref());
}
