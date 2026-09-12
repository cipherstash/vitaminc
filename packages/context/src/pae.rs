//! Pre-Authentication Encoding, the framing every composite context uses.

use std::borrow::Cow;

use crate::Context;

/// Encodes a list of byte pieces with PAE (Pre-Authentication Encoding) from
/// the PASETO specification:
///
/// ```text
/// LE64(count) || LE64(len(piece[0])) || piece[0] || LE64(len(piece[1])) || piece[1] || ...
/// ```
///
/// The encoding is injective: two different lists of pieces never encode to
/// the same bytes, so a composite context built from it can never be
/// mistaken for a composite built from different parts.
pub(crate) fn encode(pieces: &[&[u8]]) -> Context<'static> {
    let total_len = encoded_len(pieces.iter().map(|piece| piece.len()));
    let mut buf = Vec::with_capacity(total_len);
    write(&mut buf, pieces);
    // The pre-computed `total_len` is only a capacity hint, so a wrong value
    // would not change the output. Assert it matches the bytes actually
    // written, so the hint cannot silently drift from the writer.
    debug_assert_eq!(
        buf.len(),
        total_len,
        "PAE capacity hint must equal the encoded length"
    );
    Context(Cow::Owned(buf))
}

/// Appends the PAE of `pieces` to `buf`.
pub(crate) fn write(buf: &mut Vec<u8>, pieces: &[&[u8]]) {
    buf.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        buf.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        buf.extend_from_slice(piece);
    }
}

/// The length of the PAE of pieces with the given lengths: the count word,
/// then a length word per piece.
pub(crate) fn encoded_len(piece_lens: impl Iterator<Item = usize>) -> usize {
    8 + piece_lens.map(|len| 8 + len).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    mod given_the_documented_format {
        use super::*;

        #[test]
        fn no_pieces_is_the_zero_count_word() {
            assert_eq!(
                encode(&[]).as_bytes(),
                &[0u8; 8],
                "LE64(0) is eight zero bytes"
            );
        }

        #[test]
        fn one_empty_piece_is_a_count_word_and_a_zero_length_word() {
            let mut expected = vec![];
            expected.extend_from_slice(&1u64.to_le_bytes());
            expected.extend_from_slice(&0u64.to_le_bytes());
            assert_eq!(encode(&[b""]).as_bytes(), &expected);
        }

        #[test]
        fn one_piece_is_count_length_and_bytes() {
            let mut expected = vec![];
            expected.extend_from_slice(&1u64.to_le_bytes());
            expected.extend_from_slice(&4u64.to_le_bytes());
            expected.extend_from_slice(b"test");
            assert_eq!(encode(&[b"test"]).as_bytes(), &expected);
        }

        #[test]
        fn two_pieces_each_carry_their_own_length_word() {
            assert_eq!(
                encode(&[b"a", b"bc"]).as_bytes(),
                &[
                    2, 0, 0, 0, 0, 0, 0, 0, // piece count
                    1, 0, 0, 0, 0, 0, 0, 0, b'a', // first piece
                    2, 0, 0, 0, 0, 0, 0, 0, b'b', b'c', // second piece
                ]
            );
        }
    }

    /// Each case is a way an attacker might try to make two different lists
    /// of pieces read as the same bytes.
    mod given_an_attempt_to_alias_two_piece_lists {
        use super::*;

        #[test]
        fn moving_a_byte_across_a_boundary_changes_the_encoding() {
            assert_ne!(
                encode(&[b"ab", b"cd"]).as_bytes(),
                encode(&[b"a", b"bcd"]).as_bytes()
            );
        }

        #[test]
        fn a_trailing_empty_piece_is_visible() {
            assert_ne!(
                encode(&[b"foo", b"bar"]).as_bytes(),
                encode(&[b"foo", b"bar", b""]).as_bytes()
            );
        }

        #[test]
        fn a_leading_empty_piece_is_visible() {
            assert_ne!(
                encode(&[b"foo"]).as_bytes(),
                encode(&[b"", b"foo"]).as_bytes()
            );
        }

        #[test]
        fn concatenated_pieces_differ_from_one_piece() {
            assert_ne!(
                encode(&[b"foobar"]).as_bytes(),
                encode(&[b"foo", b"bar"]).as_bytes()
            );
        }

        #[test]
        fn a_fake_length_word_inside_a_piece_does_not_read_as_framing() {
            let fake_framing = {
                let mut v = Vec::new();
                v.extend_from_slice(&3u64.to_le_bytes());
                v.extend_from_slice(b"bar");
                v
            };
            assert_ne!(
                encode(&[b"foo", b"bar"]).as_bytes(),
                encode(&[&fake_framing]).as_bytes()
            );
        }

        #[test]
        fn empty_piece_lists_differ_by_count() {
            assert_ne!(
                encode(&[b"", b""]).as_bytes(),
                encode(&[b"", b"", b""]).as_bytes()
            );
        }
    }

    #[quickcheck]
    fn is_deterministic(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        encode(&refs).as_bytes() == encode(&refs).as_bytes()
    }

    #[quickcheck]
    fn output_length_matches_the_formula(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        let expected_len = 8 + pieces.iter().map(|p| 8 + p.len()).sum::<usize>();
        encode(&refs).as_bytes().len() == expected_len
            && encoded_len(pieces.iter().map(Vec::len)) == expected_len
    }

    #[quickcheck]
    fn shifting_a_boundary_is_injective(a: Vec<u8>, b: Vec<u8>) -> bool {
        // For any non-empty `a`, moving its last byte to the front of `b`
        // must produce a different encoding.
        if a.is_empty() {
            return true;
        }
        let split = a.len() - 1;
        let a1 = &a[..split];
        let mut b1 = vec![a[split]];
        b1.extend_from_slice(&b);
        encode(&[&a, &b]).as_bytes() != encode(&[a1, &b1]).as_bytes()
    }

    #[quickcheck]
    fn piece_count_is_injective(a: Vec<u8>, b: Vec<u8>) -> bool {
        let mut combined = a.clone();
        combined.extend_from_slice(&b);
        encode(&[&combined]).as_bytes() != encode(&[&a, &b]).as_bytes()
    }

    #[quickcheck]
    fn appending_an_empty_piece_changes_the_encoding(pieces: Vec<Vec<u8>>) -> bool {
        let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
        let mut with_extra = refs.clone();
        with_extra.push(b"");
        encode(&refs).as_bytes() != encode(&with_extra).as_bytes()
    }

    #[quickcheck]
    fn a_longer_list_is_never_a_prefix_match(a: Vec<u8>, b: Vec<u8>, c: Vec<u8>) -> bool {
        encode(&[&a, &b]) != encode(&[&a, &b, &c])
    }
}
