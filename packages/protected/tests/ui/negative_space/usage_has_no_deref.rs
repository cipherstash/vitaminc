use std::ops::Deref;
use vitaminc_protected::{Protected, Usage};

fn require_deref<T: Deref>(_: &T) {}

fn main() {
    let secret: Usage<Protected<String>> = Usage::new(String::from("secret"));
    require_deref(&secret);
}
