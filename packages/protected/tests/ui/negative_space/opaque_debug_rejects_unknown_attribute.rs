// An unknown key in `#[opaque_debug(...)]` must be a compile error. The derive
// used to discard the parse error, so this compiled and silently masked with
// the default `***` instead of the `###` the author asked for.
use vitaminc_protected::OpaqueDebug;

#[derive(OpaqueDebug)]
#[opaque_debug(bogus = "x", mask = "###")]
struct Token([u8; 4]);

fn main() {}
