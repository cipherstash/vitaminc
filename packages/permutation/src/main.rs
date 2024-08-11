#![warn(clippy::unwrap_used)]

use vitaminc_protected::{Paranoid, Protected};

fn main() {
    let x = Protected::new([0u8; 32]);
    println!("{:?}", x.unwrap());
}
