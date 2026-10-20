// A scheme says which targets it takes through `Supports`, so opening a
// space of another target on it does not compile, rather than returning
// `OrderError::Unsupported` on every value.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::Text;
use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::FourBytes.target(Text);
}
