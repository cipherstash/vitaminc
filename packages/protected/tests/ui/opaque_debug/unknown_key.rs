use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
#[opaque_debug(msk = "##")]
struct Token(String);

fn main() {}
