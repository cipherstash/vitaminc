// The derives look the protected crate up in the invoking package's
// manifest. This crate depends on neither `vitaminc-protected` nor
// `vitaminc`, so trybuild cases compiled here are the one place the
// "no usable dependency" path, and an override that must stand alone, can be
// exercised.
//
// `trybuild` launches rustc, which Miri cannot run.
#[cfg(not(miri))]
#[test]
fn ui() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/fail/*.rs");
    tests.pass("tests/ui/pass/*.rs");
}
