// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter. These cases run in the normal test job.
// A pass case in this same suite forces a build, not merely a check: the length
// assertions are evaluated during monomorphization.
#[cfg(not(miri))]
#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/pass/*.rs");
    tests.compile_fail("tests/ui/negative_space/*.rs");
}
