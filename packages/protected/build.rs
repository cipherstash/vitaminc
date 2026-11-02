//! Emits `cfg(memlock_limit)` on targets whose libc defines `RLIMIT_MEMLOCK`.
//!
//! `mlock` exists on every Unix this crate builds for, but the resource
//! limit that governs it does not: illumos, Solaris, AIX, Haiku and the
//! newlib targets have no `RLIMIT_MEMLOCK`. The backend, its tests and the
//! process tests all need the same answer, so it is decided once here rather
//! than as a target list repeated in each of them.
use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(memlock_limit)");
    // Set by `cargo kani`; declared here so the harness module is not an
    // unexpected cfg to an ordinary build.
    println!("cargo::rustc-check-cfg=cfg(kani)");
    // The stack residue tests state their guarantee for optimised builds:
    // at `opt-level = 0` the compiler makes argument copies of its own that
    // no wipe in this crate reaches. The level is not exposed as a `cfg`,
    // and `debug_assertions` is not the same thing (a profile can turn it
    // off without optimising), so it is read from the build script's
    // environment here.
    println!("cargo::rustc-check-cfg=cfg(vitaminc_unoptimized)");
    println!("cargo::rerun-if-env-changed=OPT_LEVEL");
    if env::var("OPT_LEVEL").as_deref() == Ok("0") {
        println!("cargo::rustc-cfg=vitaminc_unoptimized");
    }
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let has_limit = vendor == "apple"
        || matches!(
            os.as_str(),
            "linux"
                | "android"
                | "emscripten"
                | "l4re"
                | "freebsd"
                | "dragonfly"
                | "netbsd"
                | "openbsd"
                | "fuchsia"
                | "redox"
                | "nto"
                | "hurd"
        );
    if has_limit {
        println!("cargo::rustc-cfg=memlock_limit");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
