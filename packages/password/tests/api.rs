// A pass case forces trybuild to build, not merely check: const-generic
// assertions are evaluated during monomorphization. Keep it in this same suite.
#[cfg(not(miri))]
#[test]
fn generation_contract() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/pass/*.rs");
    tests.compile_fail("tests/ui/fail/*.rs");
}
