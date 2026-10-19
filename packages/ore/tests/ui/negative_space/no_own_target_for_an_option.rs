// A target is never inferred from a value, and an `Option` may be a null,
// which has no order term, so a chain that names no target refuses it:
// name the target, and the checked method.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Clear.encrypt(Some(42i64));
}
