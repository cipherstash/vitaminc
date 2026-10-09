use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
#[opaque_debug(mask = 42)]
struct Token(String);

fn main() {}
