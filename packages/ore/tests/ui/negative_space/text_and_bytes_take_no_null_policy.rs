// A null policy is for fixed-width targets: a text or bytes null already
// shows by its length, so placing it would hide nothing.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{Bytes, First, Last, Text};
use vitaminc_ore::OrderEncrypt;

fn main() {
    let _ = clear::Clear.target(Text).nulls(Last);
    let _ = clear::Clear.target(Bytes).nulls(First);
}
