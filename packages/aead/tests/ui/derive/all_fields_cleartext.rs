// An `aad` field binds the encrypted fields to itself, so a struct with none
// has nothing to bind — and, like an all-passthrough struct, no tag at all.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(aad)]
    term: Vec<u8>,
    #[aead(passthrough)]
    id: i64,
}

fn main() {}
