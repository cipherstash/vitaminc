#[test]
fn negative_space() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/negative_space/*.rs");
}
