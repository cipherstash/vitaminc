// A newtype is transparent: nothing is stored under a key, and there is no
// sibling field for the value to be bound to.
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct Term(#[aead(aad)] Vec<u8>);

fn main() {}
