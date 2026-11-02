// Without a dependency on `vitaminc-protected` or `vitaminc`, and without a
// `crate = "..."` override, the derives cannot name the protected crate. Each
// must say so and point at the fixes.
#[derive(vitaminc_protected_derive::OpaqueDebug)]
struct Token([u8; 4]);

#[derive(vitaminc_protected_derive::TimingSafeEq)]
struct Key([u8; 4]);

fn main() {}
