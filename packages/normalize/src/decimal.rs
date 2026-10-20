//! The canonical, order-preserving 14-byte encoding of a decimal.
//!
//! Ported from `orderable-bytes` 0.2.0, whose encoding is frozen: an
//! equality index stores terms under [`domain::DECIMAL`](crate::domain::DECIMAL)
//! made from these bytes, so they can never change, and this crate owns
//! them rather than reaching into a crate that is kept only for
//! cipherstash-client's stored terms. The tests check every value against
//! that release byte for byte.
//!
//! The input is the mantissa and scale a [`Logical::Decimal`](vitaminc_aead::Logical::Decimal)
//! leaf carries: `value = mantissa × 10^(-scale)`, with the mantissa in
//! `(-2^96, 2^96)` and the scale at most 28, which is `rust_decimal`'s
//! range. The encoder refuses anything outside it: a larger mantissa would
//! lose its top bits and take the bytes of another value.
//!
//! The layout is documented on [`decimal`](crate::decimal), the public
//! function that wraps this encoder, so it is in the published docs.
//!
//! ## Constant time
//!
//! Past the range check, [`orderable`] is straight-line code with
//! fixed-iteration loops and branchless mask arithmetic: no branch on the
//! sign, the zero-ness, the digit count, the trailing-zero count or the
//! scale, and no hardware division, whose latency is data-dependent on
//! some targets.

use vitaminc_aead::plaintext::kinds::MAX_DECIMAL_SCALE;
use vitaminc_protected::Protected;

use crate::scalar::fixed;

/// Width of the padded-significand field in bytes (104 bits).
const MANTISSA_BYTES: usize = 13;

/// Bias applied to `leading_exp` so it fits unsigned in the 7-bit field.
const EXP_BIAS: i32 = 64;

/// The digit count the significand is padded to: the most a 96-bit
/// mantissa has.
const PADDED_DIGITS: u32 = 29;

/// Top bit of byte 0: set for positives and zero, clear for negatives.
const SIGN_BIT: u8 = 0x80;

/// The 7-bit exponent field of byte 0.
const EXP_MASK: u8 = 0x7F;

/// One past the largest mantissa magnitude: a mantissa fits 96 bits.
const MANTISSA_LIMIT: u128 = 1 << 96;

/// The length of the encoding.
pub(crate) const ENCODED_LEN: usize = 14;

/// `5⁻¹ mod 2¹²⁸`, so that dividing by ten (when exact) is a shift and a
/// multiply rather than a hardware division.
const INV5: u128 = 0xCCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCC_CCCD;

/// The largest `u128` divisible by 5. Multiplication by [`INV5`] is a
/// bijection that maps the multiples of 5 onto `[0, MAX_DIV_5]`, so
/// `x.wrapping_mul(INV5) <= MAX_DIV_5` exactly when `5 | x`.
const MAX_DIV_5: u128 = u128::MAX / 5;

/// The encoding of `mantissa × 10^(-scale)`. Two equal values give the
/// same bytes, and the bytes sort as the values do. `None` if the mantissa
/// does not fit 96 bits or the scale is above 28.
///
/// The encoder makes the protected vector it returns and writes every
/// byte of the encoding straight into it, so no caller has to supply a
/// buffer and remember to wipe it. The working values below are plain
/// integers, which the compiler keeps in registers or short-lived stack
/// slots that Rust cannot promise to wipe.
pub(crate) fn orderable(mantissa: i128, scale: u8) -> Option<Protected<Vec<u8>>> {
    if scale > MAX_DECIMAL_SCALE || mantissa.unsigned_abs() >= MANTISSA_LIMIT {
        return None;
    }
    let scale = u32::from(scale);

    // The pipeline runs unconditionally: zero goes through the same steps
    // as every other value (the helpers give it significand 0, digits 0,
    // trailing 0) and its byte 0 is fixed up by a mask at the end, rather
    // than a short-circuit that would tell zero apart by timing.
    //
    // Branchless absolute value: `(x ^ s) - s` where `s` is the sign bit
    // arithmetically shifted across the word.
    let sign_extension = mantissa >> 127;
    let abs_mantissa = ((mantissa ^ sign_extension).wrapping_sub(sign_extension)) as u128;
    let (significand, trailing) = strip_trailing_zeros(abs_mantissa);
    let digits = digit_count(significand);

    // value = ±significand × 10^trailing × 10^(-scale); the leading digit's
    // exponent is in [-28, 28] for a non-zero value. For zero the formula
    // gives -1 - scale, in [-29, -1]: a valid-looking positive byte that is
    // overwritten below.
    let leading_exp = digits as i32 - 1 + trailing - scale as i32;
    debug_assert!(
        (-29..=28).contains(&leading_exp),
        "leading_exp {leading_exp} out of bounds: mantissa or scale out of range"
    );
    let biased_exp = (leading_exp + EXP_BIAS) as u8;
    debug_assert!(biased_exp <= EXP_MASK, "biased_exp overflowed 7 bits");

    // Pad the significand to 29 digits. Not `pow`, whose work depends on
    // its exponent: a fixed loop that multiplies by ten under a mask that
    // is set while padding remains. The product is computed every
    // iteration and never overflows: while the mask is set the value is
    // below 10^28, and once clear the unstored product is below 10^30.
    let mut padded_mantissa = significand;
    for i in 0..PADDED_DIGITS {
        let do_step = ((digits + i) < PADDED_DIGITS) as u128;
        let mask = 0u128.wrapping_sub(do_step);
        let stepped = padded_mantissa.wrapping_mul(10);
        padded_mantissa = (padded_mantissa & !mask) | (stepped & mask);
    }
    debug_assert!(
        padded_mantissa >> (8 * MANTISSA_BYTES) == 0,
        "padded mantissa overflowed 104 bits"
    );

    // One mask handles the sign: 0xFF for a negative, 0x00 otherwise. Byte
    // 0 keeps the sign bit only when positive and XORs the exponent bits
    // with the mask; each significand byte is XORed with it too.
    let neg_mask = (mantissa >> 127) as u8;

    // The zero plaintext, applied branchlessly: the tail is already all
    // zero, so only byte 0 is replaced, by the bare sign bit, when the
    // mantissa is zero.
    let mant_nonzero_bit = ((abs_mantissa | abs_mantissa.wrapping_neg()) >> 127) as u8;
    let zero_mask = 0u8.wrapping_sub(mant_nonzero_bit ^ 1);

    // Every byte is written. The significand bytes are taken from the
    // integer by shifting, most significant first, rather than through a
    // plain array of its bytes.
    Some(fixed::<ENCODED_LEN>(|out| {
        let head = (SIGN_BIT & !neg_mask) | (biased_exp ^ (neg_mask & EXP_MASK));
        out[0] = (head & !zero_mask) | (SIGN_BIT & zero_mask);
        for i in 0..MANTISSA_BYTES {
            let shift = 8 * (MANTISSA_BYTES - 1 - i);
            out[1 + i] = (padded_mantissa >> shift) as u8 ^ neg_mask;
        }
    }))
}

/// Divide by ten while the trailing digit is zero: the stripped value and
/// how many zeros were removed. Zero strips to `(0, 0)`.
///
/// A fixed `PADDED_DIGITS` iterations, each selecting by mask. Division by
/// ten, valid only when exact, is a halving and a multiply by [`INV5`];
/// divisibility by ten is divisibility by two (the low bit) and by five
/// (the [`MAX_DIV_5`] test), with the comparison done by `overflowing_sub`
/// so it lowers to a borrow rather than a branch.
fn strip_trailing_zeros(mut mantissa: u128) -> (u128, i32) {
    let mut exponent: i32 = 0;
    for _ in 0..PADDED_DIGITS {
        let div = (mantissa >> 1).wrapping_mul(INV5);
        let q5 = mantissa.wrapping_mul(INV5);
        let (_, borrow) = MAX_DIV_5.overflowing_sub(q5);
        let div_by_5 = (borrow as u128) ^ 1;
        let div_by_2 = (mantissa & 1) ^ 1;
        let div_by_10 = div_by_5 & div_by_2;
        let mantissa_nz = (mantissa | mantissa.wrapping_neg()) >> 127;
        let do_strip = mantissa_nz & div_by_10;
        let mask = 0u128.wrapping_sub(do_strip);
        mantissa = (div & mask) | (mantissa & !mask);
        exponent = exponent.wrapping_add(do_strip as i32);
    }
    (mantissa, exponent)
}

/// The number of decimal digits in `m`, `0` for zero: how many powers of
/// ten below `10^PADDED_DIGITS` it is at least, each test a borrow.
fn digit_count(m: u128) -> u32 {
    let mut n: u32 = 0;
    let mut pow: u128 = 1;
    for _ in 0..PADDED_DIGITS {
        let (_, borrow) = m.overflowing_sub(pow);
        n = n.wrapping_add((borrow as u32) ^ 1);
        pow = pow.wrapping_mul(10);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use orderable_bytes::OrderableBytes;
    use quickcheck_macros::quickcheck;
    use rust_decimal::Decimal;
    use vitaminc_protected::Controlled;

    const U96_MAX: u128 = (1u128 << 96) - 1;

    /// The encoding of an in-range value, taken out of its protected
    /// vector. The tests below index, sort and compare the bytes against
    /// another crate's plain arrays, so this is the one place they leave
    /// the wrapper.
    fn encode(mantissa: i128, scale: u32) -> [u8; ENCODED_LEN] {
        let scale = u8::try_from(scale).expect("scale fits u8");
        let bytes = orderable(mantissa, scale).expect("in range").risky_unwrap();
        <[u8; ENCODED_LEN]>::try_from(bytes).expect("the encoding is ENCODED_LEN bytes")
    }

    /// Whether the encoder accepts `mantissa` and `scale`.
    fn accepts(mantissa: i128, scale: u8) -> bool {
        orderable(mantissa, scale).is_some()
    }

    /// The frozen encoding this one was ported from.
    fn oracle(mantissa: i128, scale: u32) -> [u8; ENCODED_LEN] {
        Decimal::try_from_i128_with_scale(mantissa, scale)
            .expect("in range")
            .to_orderable_bytes()
    }

    #[test]
    fn zero_in_any_scale_or_sign_is_the_bare_sign_bit() {
        let mut expected = [0u8; ENCODED_LEN];
        expected[0] = SIGN_BIT;
        for scale in [0, 1, 3, 28] {
            assert_eq!(encode(0, scale), expected, "scale {scale}");
        }
        assert_eq!(encode(-0, 0), expected);
    }

    #[test]
    fn equivalent_forms_encode_identically() {
        let one = encode(1, 0);
        assert_eq!(encode(10, 1), one);
        assert_eq!(encode(100, 2), one);
        assert_eq!(encode(1_000, 3), one);
        // 100 strips to significand 1 at exponent 2: the same significand
        // bytes as 1, and an exponent two higher.
        let hundred = encode(100, 0);
        assert_eq!(&one[1..], &hundred[1..]);
        assert_eq!(one[0], SIGN_BIT | EXP_BIAS as u8);
        assert_eq!(hundred[0], SIGN_BIT | (2 + EXP_BIAS) as u8);
    }

    #[test]
    fn worked_examples() {
        assert_eq!(encode(5, 1)[0], SIGN_BIT | (-1 + EXP_BIAS) as u8);
        assert_eq!(encode(10, 0)[0], SIGN_BIT | (1 + EXP_BIAS) as u8);
        let (neg_one, pos_one) = (encode(-1, 0), encode(1, 0));
        assert_eq!(neg_one[0] & SIGN_BIT, 0);
        assert_eq!(neg_one[0] & EXP_MASK, !(EXP_BIAS as u8) & EXP_MASK);
        for i in 1..ENCODED_LEN {
            assert_eq!(neg_one[i], !pos_one[i]);
        }
    }

    #[test]
    fn byte_order_is_value_order() {
        let values: [(i128, u32); 13] = [
            (-(U96_MAX as i128), 0),
            (-1_000_000_000, 0),
            (-15, 1),
            (-105, 2),
            (-1, 0),
            (-1, 3),
            (0, 0),
            (1, 3),
            (1, 0),
            (105, 2),
            (15, 1),
            (1_000_000_000, 0),
            (U96_MAX as i128, 0),
        ];
        for pair in values.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            assert!(encode(a.0, a.1) < encode(b.0, b.1), "{a:?} < {b:?} failed");
        }
    }

    #[test]
    fn strip_trailing_zeros_edge_cases() {
        assert_eq!(strip_trailing_zeros(0), (0, 0));
        for d in 1u128..=9 {
            assert_eq!(strip_trailing_zeros(d), (d, 0), "input {d}");
        }
        for k in 0..=28u32 {
            assert_eq!(strip_trailing_zeros(10u128.pow(k)), (1, k as i32), "10^{k}");
        }
        assert_eq!(strip_trailing_zeros(U96_MAX), (U96_MAX, 0));
        assert_eq!(strip_trailing_zeros(12_340_000), (1234, 4));
        assert_eq!(strip_trailing_zeros(50), (5, 1));
        assert_eq!(strip_trailing_zeros(100_500), (1005, 2));
    }

    #[test]
    fn digit_count_counts_digits() {
        assert_eq!(digit_count(0), 0);
        assert_eq!(digit_count(1), 1);
        assert_eq!(digit_count(9), 1);
        assert_eq!(digit_count(10), 2);
        assert_eq!(digit_count(U96_MAX), 29);
    }

    fn u96(m: u128) -> u128 {
        m & U96_MAX
    }

    #[quickcheck]
    fn strip_reconstructs_and_is_canonical(m: u128) -> bool {
        let m = u96(m);
        let (s, c) = strip_trailing_zeros(m);
        (0..=28).contains(&c)
            && s.wrapping_mul(10u128.pow(c as u32)) == m
            && (s == 0 || s % 10 != 0)
            && (m == 0) == (s == 0)
            && strip_trailing_zeros(s) == (s, 0)
    }

    #[quickcheck]
    fn strip_distributes_over_powers_of_ten(m: u128, k: u8) -> bool {
        let (s, _) = strip_trailing_zeros(u96(m));
        let k = u32::from(k) % 29;
        match s.checked_mul(10u128.pow(k)) {
            Some(extended) if s != 0 && extended <= U96_MAX => {
                strip_trailing_zeros(extended) == (s, k as i32)
            }
            _ => true,
        }
    }

    /// Every value encodes exactly as the frozen `orderable-bytes` release
    /// encodes it.
    #[quickcheck]
    fn matches_orderable_bytes_byte_for_byte(m: u128, negative: bool, scale: u8) -> bool {
        let magnitude = u96(m) as i128;
        let mantissa = if negative { -magnitude } else { magnitude };
        let scale = u32::from(scale) % 29;
        encode(mantissa, scale) == oracle(mantissa, scale)
    }

    #[test]
    fn the_extremes_match_orderable_bytes() {
        for (mantissa, scale) in [
            (U96_MAX as i128, 0),
            (-(U96_MAX as i128), 0),
            (U96_MAX as i128, 28),
            (-(U96_MAX as i128), 28),
            (1, 28),
            (-1, 28),
            (0, 28),
        ] {
            assert_eq!(encode(mantissa, scale), oracle(mantissa, scale));
        }
    }

    #[quickcheck]
    fn byte_order_matches_decimal_order(a: u64, b: u64, sa: u8, sb: u8, neg: (bool, bool)) -> bool {
        let (sa, sb) = (u32::from(sa) % 29, u32::from(sb) % 29);
        let (a, b) = (
            if neg.0 { -(a as i128) } else { a as i128 },
            if neg.1 { -(b as i128) } else { b as i128 },
        );
        let (x, y) = (
            Decimal::try_from_i128_with_scale(a, sa).expect("in range"),
            Decimal::try_from_i128_with_scale(b, sb).expect("in range"),
        );
        encode(a, sa).cmp(&encode(b, sb)) == x.cmp(&y)
    }

    /// The encoder checks its own range, so no caller can hand it a
    /// mantissa whose top bits it would drop.
    mod given_a_mantissa_or_scale_at_the_edge_of_the_range {
        use super::*;

        #[test]
        fn returns_an_encoding() {
            let limit = 1i128 << 96;
            assert!(accepts(limit - 1, 0), "the largest mantissa is accepted");
            assert!(accepts(1 - limit, 0), "the smallest mantissa is accepted");
            assert!(accepts(1, 28), "the largest scale is accepted");
        }
    }

    mod given_a_mantissa_or_scale_one_past_the_range {
        use super::*;

        #[test]
        fn returns_none() {
            let limit = 1i128 << 96;
            assert!(
                !accepts(limit, 0),
                "one past the largest mantissa is refused"
            );
            assert!(
                !accepts(-limit, 0),
                "one past the smallest mantissa is refused"
            );
            assert!(!accepts(1, 29), "one past the largest scale is refused");
        }
    }

    /// Every digit count, with and without trailing zeros, at every scale
    /// and both signs. Random 96-bit mantissas almost all have 28 or 29
    /// digits, so the quickcheck oracle above rarely reaches short ones.
    #[test]
    fn every_digit_count_scale_and_sign_matches_orderable_bytes() {
        for k in 0..=28u32 {
            let p = 10i128.pow(k);
            for magnitude in [p, p - 1, 7 * p, 123_456_789 * p] {
                if magnitude as u128 > U96_MAX {
                    continue;
                }
                for scale in 0..=28u32 {
                    for mantissa in [magnitude, -magnitude] {
                        assert_eq!(
                            encode(mantissa, scale),
                            oracle(mantissa, scale),
                            "{mantissa} at scale {scale}"
                        );
                    }
                }
            }
        }
    }

    /// Built from a short significand, so `s * 10^k` stays in range and
    /// every case reaches the comparison.
    #[quickcheck]
    fn strip_distributes_over_powers_of_ten_for_short_significands(base: u32, k: u8) -> bool {
        let (s, _) = strip_trailing_zeros(u128::from(base));
        // `s` has at most 10 digits, so `s * 10^k` stays below 10^28.
        let k = u32::from(k) % (29 - digit_count(s));
        s == 0 || strip_trailing_zeros(s * 10u128.pow(k)) == (s, k as i32)
    }
}
