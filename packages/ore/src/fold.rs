//! Accent and case folding for text order terms.
//!
//! An order term only has to tie where values should sort together, so it
//! folds further than an equality term may: `É`, `é`, `E` and `e` all
//! become `e`. The steps are Unicode's canonical caseless matching
//! (NFD, full default case folding, NFD again; *Unicode Standard* §3.13,
//! D145) with every combining mark then dropped, and the result put back
//! into NFC. Folding before dropping marks means a precomposed letter's
//! case mapping is applied before its accent is lost, and decomposing
//! again after folding catches a mark a case mapping introduces.
//!
//! The case-folding table is generated from Unicode 16's
//! `CaseFolding.txt` and pinned, like the assignment table, so a frozen
//! domain's accepted input and output never widen with a dependency
//! upgrade.

use core::str::Chars;

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;
use vitaminc_normalize::NormalizeError;
use vitaminc_protected::{Controlled, Protected};

use crate::casefold_unicode16::FOLD;

/// The folded form of `text`, in one protected buffer sized exactly up
/// front (the pipeline runs twice, once to measure), so it never
/// reallocates and frees an unwiped partial copy. As with NFC in
/// `vitaminc_normalize`, the normalization iterators' own small buffers
/// are out of this crate's control.
pub(crate) fn folded(text: &str) -> Result<Protected<Vec<u8>>, NormalizeError> {
    if text
        .chars()
        .any(|c| get_general_category(c) == GeneralCategory::Unassigned)
    {
        return Err(NormalizeError::UnassignedCodePoint);
    }
    let len = pipeline(text).map(char::len_utf8).sum();
    let mut result = Protected::new(Vec::with_capacity(len));
    for c in pipeline(text) {
        let mut encoded = Protected::new([0u8; 4]);
        result
            .risky_inner_mut()
            .extend_from_slice(c.encode_utf8(encoded.risky_inner_mut()).as_bytes());
    }
    Ok(result)
}

/// NFD, case fold, NFD, drop marks, NFC.
fn pipeline(text: &str) -> impl Iterator<Item = char> + '_ {
    text.nfd()
        .flat_map(fold)
        .nfd()
        .filter(|&c| !is_mark(c))
        .nfc()
}

/// The full default case folding of one code point: the table's mapping,
/// or the code point itself.
///
/// Built from the standard library's finite iterators rather than a
/// hand-written `Iterator`, so there is no `next` that could fail to end.
fn fold(c: char) -> core::iter::Chain<core::option::IntoIter<char>, Chars<'static>> {
    match FOLD.binary_search_by_key(&(c as u32), |&(code, _)| code) {
        Ok(index) => None.into_iter().chain(FOLD[index].1.chars()),
        Err(_) => Some(c).into_iter().chain("".chars()),
    }
}

fn is_mark(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fold_str(s: &str) -> String {
        String::from_utf8(folded(s).expect("assigned").risky_ref().clone()).expect("utf-8")
    }

    /// One code point folds to its mapping, or to itself, and then the
    /// iterator ends.
    #[test]
    fn one_code_point_folds_and_then_ends() {
        let take = |c: char| fold(c).take(4).collect::<String>();
        assert_eq!(take('a'), "a");
        assert_eq!(take('A'), "a");
        assert_eq!(take('ß'), "ss");
        assert_eq!(take('ﬃ'), "ffi");
    }

    #[test]
    fn the_table_is_sorted_by_code_point_with_no_repeats() {
        // The lookup is a binary search, so a regenerated table that was
        // not in code point order would silently miss mappings.
        assert!(FOLD.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(!FOLD.is_empty());
    }

    #[test]
    fn accents_and_case_fold_and_the_result_is_nfc() {
        for (input, expected) in [
            ("École", "ecole"),
            ("Straße", "strasse"),
            ("Σςσ", "σσσ"),
            ("İ", "i"),
            ("ﬃ", "ffi"),
            ("\u{10400}", "\u{10428}"),
            ("e\u{301}", "e"),
            ("a\u{0903}", "a"),
            ("ÅNGSTRÖM", "angstrom"),
            ("", ""),
        ] {
            assert_eq!(fold_str(input), expected, "{input:?}");
        }
    }

    #[test]
    fn folding_is_idempotent_and_canonically_equivalent_inputs_agree() {
        for input in ["École", "Straße", "ᾈ", "ǅ", "Ⅸ", "ﬁ", "ẞ"] {
            let once = fold_str(input);
            assert_eq!(fold_str(&once), once, "{input:?}");
            let decomposed: String = input.nfd().collect();
            assert_eq!(fold_str(&decomposed), once, "{input:?}");
        }
    }

    #[test]
    fn an_unassigned_code_point_is_refused() {
        assert_eq!(
            folded("a\u{378}").expect_err("refused"),
            NormalizeError::UnassignedCodePoint
        );
    }
}
