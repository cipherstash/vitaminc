// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter. The UI cases are exercised by the
// normal test job; Miri remains focused on the crate's runtime unsafe code.
#[cfg(not(miri))]
#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/negative_space/*.rs");
    // Derive hygiene: inputs that must compile and run.
    tests.pass("tests/ui/opaque_debug/pass/*.rs");
    tests.pass("tests/ui/timing_safe/pass/*.rs");
}
