//! What the `Controlled` combinators leave on the stack.
//!
//! Moving a value whose bytes live inline (`Protected<[u8; N]>`) copies them,
//! and the slot a move leaves behind holds the secret until something else
//! overwrites it. The combinators lend the inner value to the closure where it
//! sits, and the wrapper they consume wipes it when it drops. These tests
//! check that: each case plants a marker inside a `Protected<[u8; 32]>`,
//! runs one combinator on a fresh thread, then searches the dead stack below
//! the caller for the marker.
//!
//! The technique is the one ore.rs uses for its stack scrub tests: paint the
//! stack below the caller, run the case, then copy the region out with
//! volatile reads (so the copy itself calls nothing that would overwrite it)
//! and search it.
//!
//! The wipe reaches the wrapper the combinator is given. At `opt-level = 0`
//! the compiler makes an argument copy of its own for a by-value call, which
//! is outside it, so the zero-copy cases are ignored there and the guarantee
//! is stated for optimised builds. Run with `--release` to exercise them.
//!
//! Not run under Miri: the snapshot reads dead stack through raw pointers,
//! which is outside any allocation Miri knows about.
#![cfg(not(miri))]

use core::hint::black_box;
use std::thread;
use vitaminc_protected::{Controlled, Protected};

type Array = [u8; 32];
type Case = fn(Protected<Array>) -> usize;
const MARKER: &Array = b"vitaminc residue marker: 32 byte";

/// Bytes of dead stack [`after`] copies and searches.
const SCAN_BYTES: usize = 64 * 1024;

/// Fill the stack below the caller with a marker byte, so that nothing from
/// an earlier case is mistaken for this one's residue.
#[inline(never)]
fn paint() {
    let mut buf = [0xa5u8; SCAN_BYTES + 4096];
    black_box(&mut buf);
}

/// Copy the `SCAN_BYTES` of stack below this frame into `out`, using only
/// volatile reads, so that the copy calls no function that would overwrite
/// the region first.
#[inline(never)]
fn snapshot(out: &mut [u8]) {
    let marker = 0u8;
    let top = black_box(&marker as *const u8);
    // Scan right up to `marker`: the cases are shallow, so their residue
    // sits close below this frame. This frame's own slots fall inside the
    // region too, and none of them can hold the marker.
    let start = top.wrapping_sub(out.len());
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: the region is inside this thread's stack (which `after`
        // sizes well beyond `SCAN_BYTES`), below the live frames, and mapped.
        // It is read as plain bytes.
        *slot = unsafe { core::ptr::read_volatile(start.wrapping_add(i)) };
    }
}

/// Run `f` below a padding frame, so that its residue sits deeper than the
/// frames `snapshot` and its callees use. At `opt-level = 0` nothing in the
/// snapshot loop is inlined, and without the padding those calls overwrite
/// the first few hundred bytes of the region before they are read.
#[inline(never)]
fn run<F: FnOnce()>(f: F) {
    let mut pad = [0u8; 4096];
    black_box(&mut pad);
    f()
}

/// The dead stack left by `f`, run on a fresh thread: `SCAN_BYTES`, ordered
/// from the deepest address up.
fn after<F: FnOnce() + Send + 'static>(f: F) -> Vec<u8> {
    thread::Builder::new()
        .stack_size(4 * 1024 * 1024)
        .spawn(move || {
            let mut out = vec![0u8; SCAN_BYTES];
            paint();
            run(f);
            snapshot(&mut out);
            out
        })
        .unwrap()
        .join()
        .unwrap()
}

/// How many times `needle` occurs in `dead`.
fn copies(dead: &[u8], needle: &[u8]) -> usize {
    dead.windows(needle.len()).filter(|w| *w == needle).count()
}

/// A `Protected` holding the marker, filled in place so the only copy is
/// the one inside the wrapper.
#[inline(never)]
fn planted() -> Protected<Array> {
    let mut p = Protected::new([0u8; 32]);
    p.risky_update(|a| a.copy_from_slice(black_box(MARKER)));
    p
}

// Each case takes the value by value, which is the shape the combinators are
// used in and the one that makes a move. The closures read one byte so that
// the compiler cannot drop the value as unused.

#[inline(never)]
fn by_map(p: Protected<Array>) -> usize {
    p.map(|a| black_box(a)[0] as usize).risky_unwrap()
}

#[inline(never)]
fn by_map_ok(p: Protected<Array>) -> usize {
    p.map_ok(|a| Ok::<_, ()>(black_box(a)[0] as usize))
        .unwrap()
        .risky_unwrap()
}

#[inline(never)]
fn by_zip(p: Protected<Array>) -> usize {
    p.zip(Protected::new(0usize), |a, n| black_box(a)[0] as usize + *n)
        .risky_unwrap()
}

#[inline(never)]
fn by_zip_ref(p: Protected<Array>) -> usize {
    let other = Protected::new(0usize);
    p.zip_ref(&other, |a, n: &usize| black_box(a)[0] as usize + *n)
        .risky_unwrap()
}

#[inline(never)]
fn by_risky_update_with(p: Protected<Array>) -> usize {
    let mut sink = Protected::new(0usize);
    sink.risky_update_with(p, |s, a| *s = black_box(a)[0] as usize);
    sink.risky_unwrap()
}

/// Positive control: `risky_unwrap` hands the bare array to the caller,
/// whose plain local is not wiped. The scan must see that copy, or it is
/// not looking at the right memory.
#[inline(never)]
fn by_risky_unwrap(p: Protected<Array>) -> usize {
    let bare = p.risky_unwrap();
    black_box(&bare)[0] as usize
}

fn residue(case: Case) -> usize {
    let dead = after(move || {
        assert_eq!(black_box(case(planted())), MARKER[0] as usize);
    });
    copies(&dead, MARKER)
}

mod given_the_scan {
    use super::*;

    #[test]
    fn sees_the_bare_array_risky_unwrap_hands_out() {
        assert!(
            residue(by_risky_unwrap) >= 1,
            "the scan should find the plain copy the caller is left holding"
        );
    }
}

mod given_an_inline_array_moved_into_a_combinator {
    use super::*;

    #[test]
    #[cfg_attr(
        vitaminc_unoptimized,
        ignore = "the wipe reaches the compiler's own argument copy only at opt-level 1 and above"
    )]
    fn map_leaves_no_copy() {
        assert_eq!(residue(by_map), 0, "map should leave no copy of the array");
    }

    #[test]
    #[cfg_attr(
        vitaminc_unoptimized,
        ignore = "the wipe reaches the compiler's own argument copy only at opt-level 1 and above"
    )]
    fn map_ok_leaves_no_copy() {
        assert_eq!(
            residue(by_map_ok),
            0,
            "map_ok should leave no copy of the array"
        );
    }

    #[test]
    #[cfg_attr(
        vitaminc_unoptimized,
        ignore = "the wipe reaches the compiler's own argument copy only at opt-level 1 and above"
    )]
    fn zip_leaves_no_copy() {
        assert_eq!(residue(by_zip), 0, "zip should leave no copy of the array");
    }

    #[test]
    #[cfg_attr(
        vitaminc_unoptimized,
        ignore = "the wipe reaches the compiler's own argument copy only at opt-level 1 and above"
    )]
    fn zip_ref_leaves_no_copy() {
        assert_eq!(
            residue(by_zip_ref),
            0,
            "zip_ref should leave no copy of the array"
        );
    }

    #[test]
    #[cfg_attr(
        vitaminc_unoptimized,
        ignore = "the wipe reaches the compiler's own argument copy only at opt-level 1 and above"
    )]
    fn risky_update_with_leaves_no_copy() {
        assert_eq!(
            residue(by_risky_update_with),
            0,
            "risky_update_with should leave no copy of the array"
        );
    }
}

/// Where each case leaves the marker, as offsets below the top of the scan.
/// A diagnostic for when a case fails: `cargo test --release --test
/// residue_stack -- --ignored --nocapture report`.
#[test]
#[ignore = "diagnostic: prints where each case leaves its residue"]
fn report() {
    let cases: [(&str, Case); 6] = [
        ("risky_unwrap (control)", by_risky_unwrap),
        ("map", by_map),
        ("map_ok", by_map_ok),
        ("zip", by_zip),
        ("zip_ref", by_zip_ref),
        ("risky_update_with", by_risky_update_with),
    ];
    for (name, case) in cases {
        let dead = after(move || {
            assert_eq!(black_box(case(planted())), MARKER[0] as usize);
        });
        let offsets: Vec<usize> = dead
            .windows(MARKER.len())
            .enumerate()
            .filter(|(_, w)| *w == MARKER)
            .map(|(i, _)| dead.len() - i)
            .collect();
        eprintln!(
            "{name:24} copies={} offsets_below_top={offsets:?}",
            offsets.len()
        );
    }
}
