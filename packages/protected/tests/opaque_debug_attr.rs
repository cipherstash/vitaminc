// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter.
#[cfg(not(miri))]
#[test]
fn malformed_opaque_debug_attr_is_rejected() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/opaque_debug/*.rs");
}
