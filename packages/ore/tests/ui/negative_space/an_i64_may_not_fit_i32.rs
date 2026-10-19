// An `i64` may not fit an `I32` space, so `encrypt` refuses it when the
// program is compiled and names `encrypt_checked`, which checks the value
// while it runs.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::I32;
use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Clear.target(I32).encrypt(42i64);
}
