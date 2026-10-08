//! Exercise live N-API conversions, including in package-scoped mutation runs.
#[test]
fn node_value_conformance() {
    use std::{path::Path, process::Command};
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = package
        .parent()
        .expect("packages")
        .parent()
        .expect("workspace");
    let addon = package.join("tests/addon/Cargo.toml");
    let target = workspace.join("target/napi-test-addon");
    let build = Command::new(env!("CARGO"))
        .args(["build", "--locked", "--quiet", "--manifest-path"])
        .arg(addon)
        .arg("--target-dir")
        .arg(&target)
        .output()
        .expect("run Cargo for the test addon");
    assert!(
        build.status.success(),
        "addon build: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let library = target.join("debug").join(format!(
        "{}vitaminc_napi_test_addon{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let module = target.join("addon.node");
    std::fs::copy(library, &module).expect("copy Node module");
    let result = Command::new("node")
        .arg(package.join("tests/value-conformance.cjs"))
        .arg(module)
        .output()
        .expect("Node.js is required for binding tests");
    assert!(
        result.status.success(),
        "Node conformance:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
