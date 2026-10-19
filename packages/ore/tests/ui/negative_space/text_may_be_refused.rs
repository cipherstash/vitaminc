// Text may hold a code point Unicode 16 does not assign, so no text fits
// a `Text` space: `encrypt` refuses it when the program is compiled, and
// `encrypt_checked` checks it while the program runs.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::Text;
use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Clear.target(Text).encrypt("abc");
    let _ = clear::Clear.encrypt("abc");
}
