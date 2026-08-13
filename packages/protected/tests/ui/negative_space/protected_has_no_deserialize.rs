use serde::de::DeserializeOwned;
use vitaminc_protected::Protected;

fn require_deserialize<T: DeserializeOwned>() {}

fn main() {
    require_deserialize::<Protected<String>>();
}
