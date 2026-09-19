//! Kani proof harnesses for the invariants the `unsafe` blocks in this
//! module rely on. Where the unit tests check a handful of values, these
//! hold for every input within the stated bounds.
//!
//! Kani cannot execute system calls, so the mapped backend is out of reach;
//! the arithmetic it depends on is proved here instead. An end-to-end
//! harness over `Locked` on the heap backend (allocate, read, update, drop)
//! was tried and did not solve in a usable time even for an eight-byte
//! value, so that path is left to Miri, which runs it on both backends.
//!
//! Run with `cargo kani -p vitaminc-protected`.

use super::layout::{interior_len, total_len, value_offset};
use super::wipe_raw;

/// Page sizes in use today run from 4 KiB to 64 KiB.
fn any_page() -> usize {
    let page: usize = kani::any();
    kani::assume(page.is_power_of_two() && (4096..=65536).contains(&page));
    page
}

/// A value larger than 4 GiB is not a key; the bound keeps the arithmetic
/// far from overflow, which the harnesses then confirm.
fn any_size() -> usize {
    let size: usize = kani::any();
    kani::assume(size <= 1 << 32);
    size
}

#[kani::proof]
fn the_interior_covers_the_value_in_whole_pages() {
    let page = any_page();
    let size = any_size();
    let len = interior_len(size, page);
    assert!(len >= size);
    assert!(len >= 1);
    assert!(len % page == 0);
    assert!(len - size.max(1) < page);
}

#[kani::proof]
fn the_total_is_the_interior_plus_two_guards() {
    let page = any_page();
    let len = interior_len(any_size(), page);
    let total = total_len(len, page);
    assert!(total == len + page + page);
    assert!(total % page == 0);
}

#[kani::proof]
fn the_value_is_inside_the_interior_aligned_and_against_the_end() {
    let page = any_page();
    let size = any_size();
    let align: usize = kani::any();
    kani::assume(align.is_power_of_two() && align <= page);
    let len = interior_len(size, page);
    let offset = value_offset(len, size, align);
    assert!(offset % align == 0);
    assert!(offset + size <= len);
    assert!(len - (offset + size) < align);
}

#[kani::proof]
#[kani::unwind(33)]
fn wipe_raw_zeroes_exactly_the_bytes_it_is_given() {
    let mut buf: [u8; 32] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 24);
    let before = buf;
    // SAFETY: `len <= 24 < 32`, so the range is inside `buf`.
    unsafe { wipe_raw(buf.as_mut_ptr(), len) };
    let mut i = 0;
    while i < 32 {
        if i < len {
            assert!(buf[i] == 0);
        } else {
            assert!(buf[i] == before[i]);
        }
        i += 1;
    }
}
