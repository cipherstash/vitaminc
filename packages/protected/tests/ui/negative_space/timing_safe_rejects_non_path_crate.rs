// The `crate = "..."` override is used verbatim as the protected crate's path,
// so a value that does not parse as a path must be rejected with the derive's
// own message rather than a generic parse error.
use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq)]
#[timing_safe(crate = "not a path")]
struct Key([u8; 4]);

fn main() {}
