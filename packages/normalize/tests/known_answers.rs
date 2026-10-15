//! Known answers for every term: the bytes and the domain label each scalar
//! normalizes to, pinned as literals. These are the terms the `canonical`
//! encoders of `vitaminc-aead-value` produced before ADR 0001, captured
//! from them when that crate held them, so an index written then still
//! matches one written now. A change here is a change to a frozen domain.
//!
//! The second half is the terms sink beside encryption.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::collections::BTreeMap;

use chrono::NaiveDate;
use futures_executor::block_on;
use vitaminc_aead::plaintext::kinds::chrono as conv;
use vitaminc_aead::plaintext::render;
use vitaminc_aead::seal::{AsyncCipher, Cipher};
use vitaminc_aead::{
    Context, EncryptError, Float, Int, Logical, Physical, Plaintext, Refusal, SeqSink, Sink,
    SourceError, TimeUnit, Unencryptable,
};
use vitaminc_normalize::{
    domain, encrypt_with_terms, encrypt_with_terms_async, normalize, plan_with_terms, terms,
    NormalizeError, Path, Term, TermError,
};
use vitaminc_protected::{Controlled, Protected};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[track_caller]
fn pin(ty: Option<Logical>, v: Physical<'_>, domain: &str, bytes: &str) {
    let term = normalize(ty, v).expect("normalizes");
    assert_eq!(term.domain, domain, "{ty:?} {v:?}");
    assert_eq!(hex(term.bytes.risky_ref()), bytes, "{ty:?} {v:?}");
}

#[test]
fn every_integer_width_normalizes_to_its_pinned_term() {
    pin(
        None,
        Physical::Int(Int::I8(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::U8(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I16(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::U16(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I32(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::U32(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I64(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::U64(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I128(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::U128(0)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I8(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::U8(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::I16(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::U16(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::I32(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::U32(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::I64(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::U64(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::I128(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::U128(1)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000001",
    );
    pin(
        None,
        Physical::Int(Int::I8(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::U8(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::I16(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::U16(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::I32(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::U32(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::I64(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::U64(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::I128(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::U128(5)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000000005",
    );
    pin(
        None,
        Physical::Int(Int::I8(-7)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00fffffffffffffffffffffffffffffff9",
    );
    pin(
        None,
        Physical::Int(Int::I16(-7)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00fffffffffffffffffffffffffffffff9",
    );
    pin(
        None,
        Physical::Int(Int::I32(-7)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00fffffffffffffffffffffffffffffff9",
    );
    pin(
        None,
        Physical::Int(Int::I64(-7)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00fffffffffffffffffffffffffffffff9",
    );
    pin(
        None,
        Physical::Int(Int::I128(-7)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00fffffffffffffffffffffffffffffff9",
    );
    pin(
        None,
        Physical::Int(Int::I8(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::U8(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::I16(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::U16(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::I32(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::U32(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::I64(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::U64(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::I128(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::U128(127)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000007f",
    );
    pin(
        None,
        Physical::Int(Int::I8(-128)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffffff80",
    );
    pin(
        None,
        Physical::Int(Int::I16(-128)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffffff80",
    );
    pin(
        None,
        Physical::Int(Int::I32(-128)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffffff80",
    );
    pin(
        None,
        Physical::Int(Int::I64(-128)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffffff80",
    );
    pin(
        None,
        Physical::Int(Int::I128(-128)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffffff80",
    );
    pin(
        None,
        Physical::Int(Int::U8(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::I16(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::U16(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::I32(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::U32(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::I64(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::U64(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::I128(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::U128(255)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000000000ff",
    );
    pin(
        None,
        Physical::Int(Int::U16(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::I32(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::U32(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::I64(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::U64(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::I128(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::U128(65535)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000000000ffff",
    );
    pin(
        None,
        Physical::Int(Int::I16(-32768)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffff8000",
    );
    pin(
        None,
        Physical::Int(Int::I32(-32768)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffff8000",
    );
    pin(
        None,
        Physical::Int(Int::I64(-32768)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffff8000",
    );
    pin(
        None,
        Physical::Int(Int::I128(-32768)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffffffff8000",
    );
    pin(
        None,
        Physical::Int(Int::I128(-170141183460469231731687303715884105728)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0080000000000000000000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I128(170141183460469231731687303715884105727)),
        "vitaminc/prf/value/integer-orderable/v1",
        "017fffffffffffffffffffffffffffffff",
    );
    pin(
        None,
        Physical::Int(Int::I16(32767)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000000000000000007fff",
    );
    pin(
        None,
        Physical::Int(Int::I32(-2147483648)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffffffffffff80000000",
    );
    pin(
        None,
        Physical::Int(Int::I32(2147483647)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000000000007fffffff",
    );
    pin(
        None,
        Physical::Int(Int::I64(-9223372036854775808)),
        "vitaminc/prf/value/integer-orderable/v1",
        "00ffffffffffffffff8000000000000000",
    );
    pin(
        None,
        Physical::Int(Int::I64(9223372036854775807)),
        "vitaminc/prf/value/integer-orderable/v1",
        "0100000000000000007fffffffffffffff",
    );
    pin(
        None,
        Physical::Int(Int::U32(4294967295)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01000000000000000000000000ffffffff",
    );
    pin(
        None,
        Physical::Int(Int::U64(18446744073709551615)),
        "vitaminc/prf/value/integer-orderable/v1",
        "010000000000000000ffffffffffffffff",
    );
    pin(
        None,
        Physical::Int(Int::U128(340282366920938463463374607431768211455)),
        "vitaminc/prf/value/integer-orderable/v1",
        "01ffffffffffffffffffffffffffffffff",
    );
}

#[test]
fn both_float_widths_normalize_to_their_pinned_terms() {
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x0))),
        "vitaminc/prf/value/float-orderable/v1",
        "8000000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x80000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "8000000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x3fc00000))),
        "vitaminc/prf/value/float-orderable/v1",
        "bff8000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0xbfc00000))),
        "vitaminc/prf/value/float-orderable/v1",
        "4007ffffffffffff",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x3dcccccd))),
        "vitaminc/prf/value/float-orderable/v1",
        "bfb99999a0000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x7f7fffff))),
        "vitaminc/prf/value/float-orderable/v1",
        "c7efffffe0000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x800000))),
        "vitaminc/prf/value/float-orderable/v1",
        "b810000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x7f800000))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff0000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0xff800000))),
        "vitaminc/prf/value/float-orderable/v1",
        "000fffffffffffff",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x7fc00000))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff8000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0xff800001))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff8000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F32(f32::from_bits(0x1))),
        "vitaminc/prf/value/float-orderable/v1",
        "b6a0000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x0))),
        "vitaminc/prf/value/float-orderable/v1",
        "8000000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x8000000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "8000000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x3ff8000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "bff8000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x3fb999999999999a))),
        "vitaminc/prf/value/float-orderable/v1",
        "bfb999999999999a",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x7fefffffffffffff))),
        "vitaminc/prf/value/float-orderable/v1",
        "ffefffffffffffff",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x10000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "8010000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x7ff0000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff0000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0xfff0000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "000fffffffffffff",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0x7ff8000000000000))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff8000000000000",
    );
    pin(
        None,
        Physical::Float(Float::F64(f64::from_bits(0xfff0000000000001))),
        "vitaminc/prf/value/float-orderable/v1",
        "fff8000000000000",
    );
}

#[test]
fn text_and_bytes_normalize_to_their_pinned_terms() {
    pin(
        None,
        Physical::Text(""),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "",
    );
    pin(
        None,
        Physical::Text("Ada"),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "416461",
    );
    pin(
        None,
        Physical::Text("e\u{301}"),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "c3a9",
    );
    pin(
        None,
        Physical::Text("\u{344}"),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "cc88cc81",
    );
    pin(
        None,
        Physical::Text("a\0b"),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "610062",
    );
    pin(
        None,
        Physical::Text("日本語"),
        "vitaminc/prf/value/text-nfc/unicode-16/v1",
        "e697a5e69cace8aa9e",
    );
    pin(
        None,
        Physical::Bytes(&[]),
        "vitaminc/prf/value/bytes/v1",
        "",
    );
    pin(
        None,
        Physical::Bytes(&[0x00]),
        "vitaminc/prf/value/bytes/v1",
        "00",
    );
    pin(
        None,
        Physical::Bytes(&[0x01, 0x02, 0x03]),
        "vitaminc/prf/value/bytes/v1",
        "010203",
    );
    pin(
        None,
        Physical::Bytes(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]),
        "vitaminc/prf/value/bytes/v1",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert_eq!(
        normalize(None, Physical::Text("\u{378}")).expect_err("unassigned"),
        NormalizeError::UnassignedCodePoint
    );
}

#[test]
fn dates_normalize_to_their_pinned_terms() {
    // NaiveDate::MIN, 0001-01-01, 1969-12-31, 1970-01-01, 2024-02-29, NaiveDate::MAX.
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(-96465292)),
        "vitaminc/prf/value/date-orderable/v1",
        "7a4b07af",
    );
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(-719162)),
        "vitaminc/prf/value/date-orderable/v1",
        "80000001",
    );
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(-1)),
        "vitaminc/prf/value/date-orderable/v1",
        "800af93a",
    );
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(0)),
        "vitaminc/prf/value/date-orderable/v1",
        "800af93b",
    );
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(19782)),
        "vitaminc/prf/value/date-orderable/v1",
        "800b4681",
    );
    pin(
        Some(Logical::Date),
        Physical::Int(Int::I32(95026236)),
        "vitaminc/prf/value/date-orderable/v1",
        "85b4f577",
    );
}

#[test]
fn timestamps_in_every_unit_normalize_to_their_pinned_terms() {
    // Five instants as nanoseconds, each then truncated to micros, millis
    // and seconds (a coarser unit matches the term of the instant at that
    // precision), then chrono's MIN_UTC and MAX_UTC.
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(0)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000000000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Micros)),
        Physical::Int(Int::I64(0)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000000000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(0)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000000000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Seconds)),
        Physical::Int(Int::I64(0)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000000000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(-876543211)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7fffffffffffffff075bca00",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Micros)),
        Physical::Int(Int::I64(-876544)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7fffffffffffffff075bca00",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(-877)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7fffffffffffffff0754d4c0",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Seconds)),
        Physical::Int(Int::I64(-1)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7fffffffffffffff00000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(59999999999)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000003b3b9ac618",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Micros)),
        Physical::Int(Int::I64(59999999)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000003b3b9ac618",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(59999)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000003b3b8b87c0",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Seconds)),
        Physical::Int(Int::I64(59)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000000000003b00000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(1700000000123456789)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000006553f100075bca00",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Micros)),
        Physical::Int(Int::I64(1700000000123456)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000006553f100075bca00",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(1700000000123)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000006553f1000754d4c0",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Seconds)),
        Physical::Int(Int::I64(1700000000)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800000006553f10000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(-61999999999999995000)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7ffffff19083140000001388",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Micros)),
        Physical::Int(Int::I64(-61999999999999995)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7ffffff19083140000001388",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(Int::I64(-62000000000000)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7ffffff19083140000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Seconds)),
        Physical::Int(Int::I64(-62000000000)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7ffffff19083140000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(-8334601228800000000000)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "7ffff86b730dee0000000000",
    );
    pin(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(8210266876799999999999)),
        "vitaminc/prf/value/timestamp-micros-orderable/v1",
        "800007779a0a6b7f3b9ac618",
    );
}

#[test]
fn decimals_normalize_to_their_pinned_terms() {
    // 0
    pin(
        Some(Logical::Decimal { scale: 0 }),
        Physical::Int(Int::I128(0)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "8000000000000000000000000000",
    );
    // 0.0
    pin(
        Some(Logical::Decimal { scale: 1 }),
        Physical::Int(Int::I128(0)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "8000000000000000000000000000",
    );
    // -0.00
    pin(
        Some(Logical::Decimal { scale: 2 }),
        Physical::Int(Int::I128(0)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "8000000000000000000000000000",
    );
    // 1
    pin(
        Some(Logical::Decimal { scale: 0 }),
        Physical::Int(Int::I128(1)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "c000204fce5e3e25026110000000",
    );
    // 1.0
    pin(
        Some(Logical::Decimal { scale: 1 }),
        Physical::Int(Int::I128(10)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "c000204fce5e3e25026110000000",
    );
    // 1.50
    pin(
        Some(Logical::Decimal { scale: 2 }),
        Physical::Int(Int::I128(150)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "c0003077b58d5d37839198000000",
    );
    // 1.5
    pin(
        Some(Logical::Decimal { scale: 1 }),
        Physical::Int(Int::I128(15)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "c0003077b58d5d37839198000000",
    );
    // -1.5
    pin(
        Some(Logical::Decimal { scale: 1 }),
        Physical::Int(Int::I128(-15)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "3fffcf884a72a2c87c6e67ffffff",
    );
    // 0.001
    pin(
        Some(Logical::Decimal { scale: 3 }),
        Physical::Int(Int::I128(1)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "bd00204fce5e3e25026110000000",
    );
    // 123456789.987654321
    pin(
        Some(Logical::Decimal { scale: 9 }),
        Physical::Int(Int::I128(123456789987654321)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "c80027e41b37904205f388c66800",
    );
    // 79228162514264337593543950335
    pin(
        Some(Logical::Decimal { scale: 0 }),
        Physical::Int(Int::I128(79228162514264337593543950335)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "dc00ffffffffffffffffffffffff",
    );
    // -79228162514264337593543950335
    pin(
        Some(Logical::Decimal { scale: 0 }),
        Physical::Int(Int::I128(-79228162514264337593543950335)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "23ff000000000000000000000000",
    );
    // 0.0000000000000000000000000001
    pin(
        Some(Logical::Decimal { scale: 28 }),
        Physical::Int(Int::I128(1)),
        "vitaminc/prf/value/decimal-orderable/v1",
        "a400204fce5e3e25026110000000",
    );
}

#[test]
fn a_uuid_has_a_domain_of_its_own() {
    let id = uuid::Uuid::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ]);
    let n = normalize(Some(Logical::Uuid), Physical::Bytes(id.as_bytes())).expect("uuid");
    assert_eq!(n.domain, "vitaminc/prf/value/uuid/v1");
    assert_eq!(hex(n.bytes.risky_ref()), "123456789abcdef0123456789abcdef0");
    let plain = normalize(None, Physical::Bytes(id.as_bytes())).expect("bytes");
    assert_eq!(hex(plain.bytes.risky_ref()), hex(n.bytes.risky_ref()));
    assert_ne!(plain.domain, n.domain);
    // The uuid source carries its logical type, so the two never meet.
    let mut terms = Vec::new();
    let (_, ()) = id
        .visit(vitaminc_aead::Tee(
            vitaminc_aead::EncryptSink::<()>::root(()),
            vitaminc_normalize::Terms::new(&mut terms),
        ))
        .expect("walks");
    assert_eq!(terms[0].normalized.domain, domain::UUID);
}

#[test]
fn a_date_never_matches_its_day_count_and_widths_agree() {
    let date = NaiveDate::from_ymd_opt(2024, 2, 29).expect("date");
    let days = conv::date_days(date);
    let as_date = normalize(Some(Logical::Date), Physical::Int(Int::I32(days))).expect("date");
    let as_int = normalize(None, Physical::Int(Int::I32(days))).expect("int");
    assert_ne!(as_date.domain, as_int.domain);
    assert_ne!(as_date.bytes.risky_ref(), as_int.bytes.risky_ref());
    let narrow = normalize(None, Physical::Int(Int::I8(34))).expect("i8");
    let wide = normalize(None, Physical::Int(Int::U64(34))).expect("u64");
    assert_eq!(narrow.domain, wide.domain);
    assert_eq!(narrow.bytes.risky_ref(), wide.bytes.risky_ref());
}

// The terms sink beside encryption.

#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

/// Seals in the clear and counts calls, so a test can see when the cipher
/// first runs.
#[derive(Default)]
struct Counting {
    calls: AtomicUsize,
}

impl Cipher for Counting {
    type Leaf = Leaf;
    type Error = Refused;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Leaf {
            aad: aad.as_bytes().to_vec(),
            plaintext: plaintext.risky_unwrap(),
        })
    }

    fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
        if leaf.aad != aad.as_bytes() {
            return Err(Refused);
        }
        Ok(Protected::new(leaf.plaintext))
    }
}

fn user() -> BTreeMap<&'static str, Vec<Option<u32>>> {
    let mut m = BTreeMap::new();
    m.insert("ages", vec![Some(36), None, Some(41)]);
    m.insert("empty", vec![]);
    m
}

fn paths(terms: &[Term]) -> Vec<String> {
    terms.iter().map(|t| render(&t.path)).collect()
}

/// What `Terms` refused inside an encryption error, and where.
fn term_error(err: &EncryptError<Refused>) -> Option<(NormalizeError, String)> {
    match err {
        EncryptError::Source(source) => source
            .inner()
            .downcast_ref::<TermError>()
            .map(|t| (t.error(), render(t.path()))),
        _ => None,
    }
}

fn refused(error: NormalizeError, at: &str) -> Option<(NormalizeError, String)> {
    Some((error, at.to_owned()))
}

#[test]
fn plan_with_terms_has_every_term_without_a_cipher() {
    let (planned, terms) = plan_with_terms::<_, Refused, _>(user(), "ctx").expect("plans");
    assert_eq!(paths(&terms), [".ages[0]", ".ages[2]"]);
    assert_eq!(terms[0].normalized.domain, domain::INTEGER);
    assert_eq!(
        terms[1].normalized.bytes.risky_ref(),
        normalize(None, Physical::Int(Int::U32(41)))
            .expect("int")
            .bytes
            .risky_ref()
    );
    // The plan is the same one `encrypt` would seal.
    let sealed = vitaminc_aead::seal::seal_all(&Counting::default(), planned).expect("seals");
    assert!(matches!(sealed, vitaminc_aead::CipherText::Map(_)));
}

#[test]
fn encrypt_with_terms_seals_the_same_leaves_and_returns_the_terms() {
    let cipher = Counting::default();
    let (sealed, terms) = encrypt_with_terms(user(), &cipher, "ctx").expect("encrypts");
    assert_eq!(terms.len(), 2);
    // Three elements, one empty marker.
    assert_eq!(cipher.calls.load(Ordering::SeqCst), 4);
    let back: BTreeMap<String, Vec<Option<u32>>> =
        vitaminc_aead::decrypt(&cipher, sealed, "ctx").expect("decrypts");
    assert_eq!(back["ages"], [Some(36), None, Some(41)]);
}

#[test]
fn scalars_without_a_domain_and_passthroughs_get_no_term() {
    struct Doc;
    impl Plaintext for Doc {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            use vitaminc_aead::MapSink;
            let mut map = sink.map(Some(5))?;
            true.visit(map.entry("active")?)?;
            None::<u32>.visit(map.entry("missing")?)?;
            map.entry("tenant")?.passthrough("acme")?;
            vitaminc_aead::Raw(Some(Logical::Undefined), Physical::Null)
                .visit(map.entry("undefined")?)?;
            "Ada".visit(map.entry("name")?)?;
            map.end()
        }
    }
    let (_, terms) = plan_with_terms::<_, Refused, _>(Doc, "ctx").expect("plans");
    assert_eq!(paths(&terms), [".name"]);
    assert_eq!(terms[0].normalized.domain, domain::TEXT);
}

/// A logical type this build does not know means something to the client
/// that sent it, so it is refused rather than encrypted with no term.
#[test]
fn an_unknown_logical_type_stops_the_walk() {
    let newer = vitaminc_aead::Raw(
        Some(Logical::from_wire(200, 0).expect("unknown")),
        Physical::Int(Int::I32(1)),
    );
    let err = plan_with_terms::<_, Refused, _>(vec![newer], "ctx")
        .err()
        .expect("refused");
    assert_eq!(term_error(&err), refused(NormalizeError::NoDomain, "[0]"));
}

/// Nested paths are the container's path plus the step, at every depth.
#[test]
fn paths_follow_the_nesting() {
    let mut inner = BTreeMap::new();
    inner.insert("k", vec![vec![1u8, 2]]);
    let mut outer = BTreeMap::new();
    outer.insert("m", vec![inner]);
    let (_, terms) = plan_with_terms::<_, Refused, _>(outer, "ctx").expect("plans");
    assert_eq!(paths(&terms), [".m[0].k[0]"]);
    assert_eq!(terms[0].normalized.domain, domain::BYTES);
}

/// Every container on a path shares one buffer of keys, and each starts
/// over where its own keys begin, so a path names only its own keys
/// however many siblings went before it.
#[test]
fn sibling_paths_name_only_their_own_keys() {
    let mut first = BTreeMap::new();
    first.insert("x", vec!["1", "2"]);
    first.insert("yy", vec!["3"]);
    let mut second = BTreeMap::new();
    second.insert("zzz", vec!["4"]);
    let mut doc = BTreeMap::new();
    doc.insert("a", vec![first.clone(), second]);
    doc.insert("bb", vec![first]);
    for found in [
        plan_with_terms::<_, Refused, _>(doc.clone(), "ctx")
            .expect("plans")
            .1,
        terms(doc).expect("walks"),
    ] {
        assert_eq!(
            paths(&found),
            [
                ".a[0].x[0]",
                ".a[0].x[1]",
                ".a[0].yy[0]",
                ".a[1].zzz[0]",
                ".bb[0].x[0]",
                ".bb[0].x[1]",
                ".bb[0].yy[0]",
            ]
        );
    }
}

#[test]
fn an_unassigned_code_point_stops_the_walk_with_the_normalize_error() {
    let err = plan_with_terms::<_, Refused, _>("\u{378}", "ctx")
        .err()
        .expect("refused");
    assert_eq!(
        term_error(&err),
        refused(NormalizeError::UnassignedCodePoint, "")
    );
}

/// The refusal names the field, nested at any depth, through an accessor
/// only: neither the message nor `Debug` shows a key.
#[test]
fn a_refusal_names_the_field_only_on_request() {
    let mut inner = BTreeMap::new();
    inner.insert("ada@example.com", vec!["ok", "\u{378}"]);
    let mut outer = BTreeMap::new();
    outer.insert("emails", vec![inner]);
    let err = plan_with_terms::<_, Refused, _>(outer, "ctx")
        .err()
        .expect("refused");
    assert_eq!(
        term_error(&err),
        refused(
            NormalizeError::UnassignedCodePoint,
            ".emails[0].ada@example.com[1]"
        )
    );
    let EncryptError::Source(source) = &err else {
        panic!("{err:?}")
    };
    let term = source
        .inner()
        .downcast_ref::<TermError>()
        .expect("a term error");
    assert_eq!(
        term.to_string(),
        "no equality term: text contains a code point unassigned in Unicode 16"
    );
    for shown in [format!("{term:?}"), format!("{err:?}")] {
        assert!(!shown.contains("ada"), "{shown}");
        assert!(!shown.contains("emails"), "{shown}");
        assert!(shown.contains("UnassignedCodePoint"), "{shown}");
        assert!(shown.contains("Index(1)"), "{shown}");
    }
}

/// Every error in a chain, from `err` down through each `source()`.
fn chain<'e>(
    err: &'e (dyn core::error::Error + 'static),
) -> Vec<&'e (dyn core::error::Error + 'static)> {
    core::iter::successors(Some(err), |e| e.source()).collect()
}

/// A reporter that walks `source()` reaches the `NormalizeError` behind a
/// refusal, whether it arrived through encryption or through `terms`.
#[test]
fn the_normalize_error_is_on_the_source_chain() {
    let reason = |err: &(dyn core::error::Error + 'static)| {
        chain(err)
            .into_iter()
            .find_map(|e| e.downcast_ref::<NormalizeError>().copied())
    };
    let encrypting = plan_with_terms::<_, &str, _>(vec!["\u{378}"], "ctx")
        .err()
        .expect("refused");
    assert_eq!(
        reason(&encrypting),
        Some(NormalizeError::UnassignedCodePoint)
    );
    let alone = terms(vec!["\u{378}"]).expect_err("refused");
    assert_eq!(reason(&alone), Some(NormalizeError::UnassignedCodePoint));
    // The chain ends at the reason, which says why and nothing more.
    let last = chain(&alone).pop().expect("a chain");
    assert!(last.source().is_none());
    assert_eq!(
        last.to_string(),
        "text contains a code point unassigned in Unicode 16"
    );
    // `TermError` itself names its reason as its source.
    let term = alone.term().expect("refused by Terms");
    let source = core::error::Error::source(term).expect("a source");
    assert_eq!(
        source.downcast_ref::<NormalizeError>(),
        Some(&NormalizeError::UnassignedCodePoint)
    );
}

#[test]
fn terms_collects_every_term_without_encrypting() {
    let found = terms(user()).expect("walks");
    assert_eq!(paths(&found), [".ages[0]", ".ages[2]"]);
    assert_eq!(found[1].normalized.domain, domain::INTEGER);
    // A borrowed value walks too, and a scalar at the root has no steps.
    let name = String::from("Ada");
    let found = terms(&name).expect("walks");
    assert_eq!(paths(&found), [""]);
    assert!(terms(Vec::<u32>::new()).expect("walks").is_empty());
}

#[test]
fn terms_says_which_field_it_refused() {
    let mut doc = BTreeMap::new();
    doc.insert("x", "\u{378}");
    let err = terms(doc).expect_err("refused");
    let term = err.term().expect("refused by Terms");
    assert!(err.refusal().is_none());
    assert_eq!(term.error(), NormalizeError::UnassignedCodePoint);
    assert_eq!(render(term.path()), ".x");
    assert_eq!(
        err.to_string(),
        "no equality term: text contains a code point unassigned in Unicode 16"
    );

    // A value invalid for its logical type cannot be encrypted, so it is
    // refused for its shape, as encryption refuses it, before it is
    // normalized.
    let invalid = vitaminc_aead::Raw(Some(Logical::Undefined), Physical::Int(Int::I32(1)));
    let mut doc = BTreeMap::new();
    doc.insert("x", invalid);
    let err = terms(doc).expect_err("refused");
    assert!(err.term().is_none());
    let refusal = err.refusal().expect("refused for its shape");
    assert_eq!(refusal.reason(), Unencryptable::InvalidValue);
    assert_eq!(render(refusal.path()), ".x");
    assert_eq!(err.to_string(), "value is not valid for its logical type");
}

#[test]
fn terms_passes_a_source_failure_through() {
    struct Throws;
    impl Plaintext for Throws {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut seq = sink.seq(None)?;
            1u32.visit(seq.element()?)?;
            Err(<S::Error as vitaminc_aead::plaintext::Error>::source(
                SourceError::msg("getter threw"),
            ))
        }
    }
    let err = terms(Throws).expect_err("refused");
    assert!(err.term().is_none());
    assert_eq!(err.to_string(), "getter threw");
    assert_eq!(err.source_error().to_string(), "getter threw");
}

/// Seals through an await, and checks that the source's walk had finished
/// before the first one.
struct Remote {
    walked: &'static AtomicBool,
}

impl AsyncCipher for Remote {
    type Leaf = Leaf;
    type Error = Refused;

    async fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: Context<'static>,
    ) -> Result<Leaf, Refused> {
        assert!(
            self.walked.load(Ordering::SeqCst),
            "sealed before the walk ended"
        );
        Counting::default().seal(plaintext, &aad)
    }

    async fn open(&self, leaf: Leaf, aad: Context<'static>) -> Result<Protected<Vec<u8>>, Refused> {
        Counting::default().open(leaf, &aad)
    }
}

#[test]
fn encrypt_with_terms_async_has_every_term_before_its_first_await() {
    static WALKED: AtomicBool = AtomicBool::new(false);
    struct Source;
    impl Plaintext for Source {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let out = vec![1u32, 2].visit(sink);
            WALKED.store(true, Ordering::SeqCst);
            out
        }
    }
    let remote = Remote { walked: &WALKED };
    let future = encrypt_with_terms_async(Source, &remote, "ctx");
    // The walk ran, and the terms exist, before the future is polled.
    assert!(WALKED.load(Ordering::SeqCst));
    fn assert_send<T: Send>(t: T) -> T {
        t
    }
    let (sealed, terms) = block_on(assert_send(future)).expect("encrypts");
    assert_eq!(paths(&terms), ["[0]", "[1]"]);
    let back: Vec<u32> =
        block_on(vitaminc_aead::decrypt_async(&remote, sealed, "ctx")).expect("decrypts");
    assert_eq!(back, [1, 2]);
}

/// A cipher that must never be reached.
struct Never;

impl AsyncCipher for Never {
    type Leaf = Leaf;
    type Error = Refused;

    async fn seal(&self, _: Protected<Vec<u8>>, _: Context<'static>) -> Result<Leaf, Refused> {
        panic!("sealed after the walk was refused")
    }

    async fn open(&self, _: Leaf, _: Context<'static>) -> Result<Protected<Vec<u8>>, Refused> {
        Err(Refused)
    }
}

fn is_unassigned(err: &EncryptError<Refused>) -> bool {
    term_error(err) == refused(NormalizeError::UnassignedCodePoint, "[1]")
}

/// The walk ends before any leaf is sealed, so a value `Terms` refuses
/// reaches no cipher, even when its first element was fine; the async
/// future holds the refusal and returns it on its first poll.
#[test]
fn a_refused_walk_never_reaches_the_cipher() {
    let doc = || vec!["ok", "\u{378}"];
    let cipher = Counting::default();
    let err = encrypt_with_terms(doc(), &cipher, "ctx").expect_err("refused");
    assert!(is_unassigned(&err), "{err:?}");
    assert_eq!(cipher.calls.load(Ordering::SeqCst), 0);
    let err = block_on(encrypt_with_terms_async(doc(), &Never, "ctx")).expect_err("refused");
    assert!(is_unassigned(&err), "{err:?}");
}

/// `Terms` is public and works without `EncryptSink` in front of it, and
/// then refuses a value invalid for its logical type itself, as
/// encryption would. The refusal arrives through its partner's error type
/// as a source error.
#[test]
fn terms_alone_refuses_a_value_invalid_for_its_logical_type() {
    use vitaminc_aead::Raw;
    use vitaminc_normalize::Terms;

    // A scalar at the root has an empty path.
    let mut out = Vec::new();
    let sink: Terms<'_, EncryptError<Refused>> = Terms::new(&mut out);
    "Ada".visit(sink).expect("walks");
    assert_eq!(paths(&out), [""]);

    let mut out = Vec::new();
    let sink: Terms<'_, EncryptError<Refused>> = Terms::new(&mut out);
    let err = Raw(Some(Logical::Undefined), Physical::Int(Int::I32(1)))
        .visit(sink)
        .expect_err("refused");
    let EncryptError::Source(source) = &err else {
        panic!("{err:?}")
    };
    let refusal = source
        .inner()
        .downcast_ref::<Refusal>()
        .expect("refused for its shape");
    assert_eq!(refusal.reason(), Unencryptable::InvalidValue);
    assert_eq!(refusal.path(), &Path::default());
    assert!(out.is_empty());
}

/// `EncryptSink` runs first in the `Tee`, so a value invalid for its
/// logical type is a shape error from encryption, not a normalize error.
#[test]
fn an_invalid_logical_value_is_refused_by_the_encrypt_sink_first() {
    let invalid = vitaminc_aead::Raw(Some(Logical::Date), Physical::Text("2024-01-01"));
    let err = plan_with_terms::<_, Refused, _>(invalid, "ctx")
        .err()
        .expect("refused");
    assert!(matches!(err, EncryptError::Shape(_)), "{err:?}");
}
