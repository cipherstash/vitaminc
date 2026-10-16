// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter. The UI cases are exercised by the
// normal test job; Miri remains focused on the crate's runtime unsafe code.
#[cfg(not(miri))]
#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/negative_space/*.rs");
}

/// Derive hygiene: inputs that must compile and run. Each case is its own
/// crate, so items and lint levels at its root reach the derived code exactly
/// as they would in a caller's crate.
#[cfg(not(miri))]
#[test]
fn derive_hygiene() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/opaque_debug/pass/*.rs");
    tests.pass("tests/ui/timing_safe/pass/*.rs");
}
