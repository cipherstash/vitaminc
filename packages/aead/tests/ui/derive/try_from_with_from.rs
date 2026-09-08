// Both name the type to decrypt as, and only one conversion can run.
use vitaminc_aead::Decrypt;

#[derive(Decrypt)]
#[aead(try_from = "String", from = "String")]
struct Code(String);

fn main() {}
