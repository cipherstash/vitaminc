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
//! range. The caller checks that; the encoder assumes it.
//!
//! ## Encoding (scientific form, base 10)
//!
//! Each non-zero value is re-expressed in signed scientific form:
//!
//! ```text
//! value = ±significand × 10^(leading_exp − digits(significand) + 1)
//! ```
//!
//! where `significand` is the mantissa with trailing zeros stripped and
//! `leading_exp` is the decimal exponent of the leading significant digit,
//! in `[-28, 28]`. The 14 bytes are:
//!
//! ```text
//! byte 0       : [sign:1][biased_exp:7]
//! bytes 1..=13 : padded_significand (104 bits, big-endian)
//! ```
//!
//! - The sign bit is `1` for positive and zero, `0` for negative, so every
//!   negative sorts below zero and zero below every positive.
//! - The biased exponent is `leading_exp + 64`, in `[36, 92]` for a
//!   non-zero value. Zero uses `0`, which no non-zero value reaches.
//! - The padded significand is the significand left-justified to 29
//!   digits by appending zeros, so values at one exponent compare
//!   byte-wise however many digits they have. A 96-bit mantissa has at
//!   most 29 digits, so the padded value fits 104 bits.
//!
//! For a negative, the exponent bits and the significand are inverted, so
//! a larger magnitude sorts lower. `1`, `1.0` and `1.00` reduce to the
//! same significand and exponent, and `+0` and `-0` to the same zero, so
//! equal values are equal bytes, as `rust_decimal` compares them.
//!
//! ## Constant time
//!
//! [`orderable`] is straight-line code with fixed-iteration loops and
//! branchless mask arithmetic: no branch on the sign, the zero-ness, the
//! digit count, the trailing-zero count or the scale, and no hardware
//! division, whose latency is data-dependent on some targets.

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
/// same bytes, and the bytes sort as the values do.
pub(crate) fn orderable(mantissa: i128, scale: u32) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];

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
    let mant_be = padded_mantissa.to_be_bytes();
    debug_assert!(
        mant_be[..16 - MANTISSA_BYTES].iter().all(|&b| b == 0),
        "padded mantissa overflowed 104 bits"
    );
    let mant_field = &mant_be[16 - MANTISSA_BYTES..];

    // One mask handles the sign: 0xFF for a negative, 0x00 otherwise. Byte
    // 0 keeps the sign bit only when positive and XORs the exponent bits
    // with the mask; each significand byte is XORed with it too.
    let neg_mask = (mantissa >> 127) as u8;
    out[0] = (SIGN_BIT & !neg_mask) | (biased_exp ^ (neg_mask & EXP_MASK));
    for (i, &b) in mant_field.iter().enumerate() {
        out[1 + i] = b ^ neg_mask;
    }

    // The zero plaintext, applied branchlessly: the tail is already all
    // zero, so only byte 0 is replaced, by the bare sign bit, when the
    // mantissa is zero.
    let mant_nonzero_bit = ((abs_mantissa | abs_mantissa.wrapping_neg()) >> 127) as u8;
    let zero_mask = 0u8.wrapping_sub(mant_nonzero_bit ^ 1);
    out[0] = (out[0] & !zero_mask) | (SIGN_BIT & zero_mask);
    out
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

    const U96_MAX: u128 = (1u128 << 96) - 1;

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
            assert_eq!(orderable(0, scale), expected, "scale {scale}");
        }
        assert_eq!(orderable(-0, 0), expected);
    }

    #[test]
    fn equivalent_forms_encode_identically() {
        let one = orderable(1, 0);
        assert_eq!(orderable(10, 1), one);
        assert_eq!(orderable(100, 2), one);
        assert_eq!(orderable(1_000, 3), one);
        // 100 strips to significand 1 at exponent 2: the same significand
        // bytes as 1, and an exponent two higher.
        let hundred = orderable(100, 0);
        assert_eq!(&one[1..], &hundred[1..]);
        assert_eq!(one[0], SIGN_BIT | EXP_BIAS as u8);
        assert_eq!(hundred[0], SIGN_BIT | (2 + EXP_BIAS) as u8);
    }

    #[test]
    fn worked_examples() {
        assert_eq!(orderable(5, 1)[0], SIGN_BIT | (-1 + EXP_BIAS) as u8);
        assert_eq!(orderable(10, 0)[0], SIGN_BIT | (1 + EXP_BIAS) as u8);
        let (neg_one, pos_one) = (orderable(-1, 0), orderable(1, 0));
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
            assert!(
                orderable(a.0, a.1) < orderable(b.0, b.1),
                "{a:?} < {b:?} failed"
            );
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
        orderable(mantissa, scale) == oracle(mantissa, scale)
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
            assert_eq!(orderable(mantissa, scale), oracle(mantissa, scale));
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
        orderable(a, sa).cmp(&orderable(b, sb)) == x.cmp(&y)
    }
}
