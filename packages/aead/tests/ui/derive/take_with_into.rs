// `into` converts the whole value and never reads a field, so there is
// nothing for `take` to take; one of the two is not doing what the author
// believes, and the derive says so rather than picking.
use vitaminc_aead::Encrypt;

#[derive(Encrypt)]
#[aead(take, into = "String")]
struct Secret(String);

fn main() {}
