// An unknown key in `#[timing_safe(...)]` must be a compile error rather than
// being ignored; `crate = "..."` is the only key the derive accepts.
use vitaminc_protected::TimingSafeEq;

#[derive(TimingSafeEq)]
#[timing_safe(bogus = "x")]
struct Key([u8; 4]);

fn main() {}
