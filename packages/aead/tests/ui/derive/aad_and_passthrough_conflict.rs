// `aad` is `passthrough` plus a binding, so asking for both leaves it ambiguous
// which was meant.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(aad, passthrough)]
    term: Vec<u8>,
    ssn: String,
}

fn main() {}
