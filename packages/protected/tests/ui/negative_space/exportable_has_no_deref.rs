use std::ops::Deref;
use vitaminc_protected::{Exportable, Protected};

fn require_deref<T: Deref>(_: &T) {}

fn main() {
    let secret: Exportable<Protected<String>> = Exportable::new(String::from("secret"));
    require_deref(&secret);
}
