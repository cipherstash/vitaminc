// A space that places nulls is its own space, so its terms do not compare
// with the plain space's of the same target.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::I32;
use vitaminc_ore::{NullOrder, OrderEncrypt};

fn main() {
    let plain = clear::Clear.target(I32);
    let last = plain.nulls(NullOrder::Last);
    let (a, b) = (plain.encrypt(1i32).unwrap(), last.encrypt_checked(1i32).unwrap());
    let _ = plain.compare(&a, &b);
}
