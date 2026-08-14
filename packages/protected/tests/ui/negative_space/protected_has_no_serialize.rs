use serde::Serialize;
use vitaminc_protected::Protected;

fn require_serialize<T: Serialize>(_: &T) {}

fn main() {
    require_serialize(&Protected::new(String::from("secret")));
}
