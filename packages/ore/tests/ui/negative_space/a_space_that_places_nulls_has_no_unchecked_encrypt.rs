// A space that places nulls refuses its target's maximum, so even a value
// that fits the target is checked while the program runs.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{Last, I32};
use vitaminc_ore::OrderEncrypt;

fn main() {
    let ages = clear::Clear.target(I32).nulls(Last);
    let _ = ages.encrypt(1i32);
}
