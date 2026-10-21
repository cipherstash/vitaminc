// A null policy is for fixed-width targets: a text or bytes null already
// shows by its length, so placing it would hide nothing.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::{Bytes, Text};
use vitaminc_ore::{NullOrder, OrderEncrypt};

fn main() {
    let _ = clear::Clear.target(Text).nulls(NullOrder::Last);
    let _ = clear::Clear.target(Bytes).nulls(NullOrder::First);
}
