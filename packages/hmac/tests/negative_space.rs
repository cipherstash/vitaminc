// `trybuild` launches rustc and inspects the filesystem, so these cases run
// in the normal test job only.
#[cfg(not(miri))]
#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/negative_space/*.rs");
}
