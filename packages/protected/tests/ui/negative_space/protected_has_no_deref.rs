use std::ops::Deref;
use vitaminc_protected::Protected;

fn require_deref<T: Deref>(_: &T) {}

fn main() {
    require_deref(&Protected::new(String::from("secret")));
}
