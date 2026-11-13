// No ordering operator compares bytes, so an order term over them reveals
// the order of the rows and answers no query. Bytes are not `Orderable`: a
// chain that names no target refuses them, and they go into `Bytes` only
// when it is named.
#[path = "../clear.rs"]
mod clear;

use vitaminc_ore::target::Bytes;
use vitaminc_ore::{OrderEncrypt, Orderable};

fn orderable<T: Orderable>() {}

fn main() {
    let _ = clear::Clear.encrypt(vec![1u8]);
    let _ = clear::Clear.encrypt_checked(&b"raw"[..]);
    orderable::<Vec<u8>>();
    orderable::<&Vec<u8>>();
    orderable::<[u8; 4]>();
    orderable::<&[u8; 4]>();
    orderable::<vitaminc_aead::Bytes<'static>>();
    orderable::<&vitaminc_aead::Bytes<'static>>();
    let _ = clear::Clear.target(Bytes).encrypt(vec![1u8]);
}
