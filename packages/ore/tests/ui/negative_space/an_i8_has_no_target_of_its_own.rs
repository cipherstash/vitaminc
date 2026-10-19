// There is no 8-bit target: an order term over 256 possible values gives
// them away. So an `i8` has no target of its own, and a chain that names
// none refuses it; it goes into a wider target, by name.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Clear.encrypt(42i8);
}
