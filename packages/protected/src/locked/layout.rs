//! The arithmetic behind a region's shape, kept pure so it can be tested by
//! value here, mutated by cargo-mutants, and proved for every input by Kani
//! (`proofs.rs`), independently of any operating system.

/// The interior that holds a value of `size` bytes: at least one page, so a
/// zero-sized value still has real storage with a guard either side, and a
/// whole number of pages, so the guards stay page-aligned.
pub(super) fn interior_len(size: usize, page: usize) -> usize {
    size.max(1).div_ceil(page) * page
}

/// The whole mapping: a guard page, the interior, a guard page. Both the
/// map and the unmap go through here, so the two lengths cannot drift.
pub(super) fn total_len(interior_len: usize, page: usize) -> usize {
    interior_len + 2 * page
}

/// Where a value of `size` bytes at `align` sits inside an interior of
/// `interior_len` bytes: as close to the end as its alignment allows, so a
/// write past the value reaches the trailing guard within `align` bytes
/// instead of wandering through the rest of the page. `size` must not
/// exceed `interior_len`, and `align` must be a power of two.
pub(super) fn value_offset(interior_len: usize, size: usize, align: usize) -> usize {
    (interior_len - size) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interior_is_whole_pages_and_never_empty() {
        assert_eq!(interior_len(0, 4096), 4096);
        assert_eq!(interior_len(1, 4096), 4096);
        assert_eq!(interior_len(4096, 4096), 4096);
        assert_eq!(interior_len(4097, 4096), 8192);
        assert_eq!(interior_len(3, 16384), 16384);
    }

    #[test]
    fn the_total_is_the_interior_plus_a_guard_page_each_side() {
        assert_eq!(total_len(4096, 4096), 3 * 4096);
        assert_eq!(total_len(2 * 16384, 16384), 4 * 16384);
    }

    #[test]
    fn the_value_sits_as_close_to_the_end_as_its_alignment_allows() {
        assert_eq!(value_offset(4096, 32, 1), 4064);
        assert_eq!(value_offset(4096, 24, 16), 4064);
        assert_eq!(value_offset(4096, 4096, 1), 0);
        assert_eq!(value_offset(8192, 100, 64), 8064);
    }
}
