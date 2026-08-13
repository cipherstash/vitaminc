use std::ops::Deref;
use vitaminc_protected::{Equatable, Protected};

fn require_deref<T: Deref>(_: &T) {}

fn main() {
    let secret: Equatable<Protected<String>> = Equatable::new(String::from("secret"));
    require_deref(&secret);
}
