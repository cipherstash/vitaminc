// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter. The UI cases are exercised by the
// normal test job.
#[cfg(not(miri))]
#[test]
fn opaque_debug_ui() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/opaque_debug/pass/*.rs");
}
