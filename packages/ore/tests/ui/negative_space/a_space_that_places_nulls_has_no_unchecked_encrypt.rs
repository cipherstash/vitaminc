// A space that places nulls refuses its target's maximum, so even a value
// that fits the target is checked while the program runs.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::I32;
use vitaminc_ore::{NullOrder, OrderEncrypt};

fn main() {
    let ages = clear::Clear.target(I32).nulls(NullOrder::Last);
    let _ = ages.encrypt(1i32);
}
