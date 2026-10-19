// A scheme that answers for markers but not for `OrderTarget` has not
// said what it takes when the target is chosen while the program runs, so
// no space of any target opens on it. `supports_targets!` writes both
// answers from one list.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::I32;
use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Forgetful.target(I32);
}
