//! What the typed API refuses to compile: a value that may not fit its
//! target, two targets' terms in one comparison, a target the scheme does
//! not take, a value with no target of its own, a null policy on text or
//! bytes, an unchecked value in a space that places nulls, a term of such
//! a space in the plain space's comparison, and a term of one null policy
//! in the other's.

// `trybuild` launches rustc and inspects the filesystem, so these cases run
// in the normal test job only.
#[cfg(not(miri))]
#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/negative_space/*.rs");
}
