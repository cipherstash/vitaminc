//! Property tests for the value codec: random trees round-trip, and any
//! bytes the decoder accepts re-encode to exactly those bytes.

use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use vitaminc_protected::Protected;

use super::*;

/// A random `Value` tree covering every variant, depth-bounded so the
/// decoder's nesting limit is never the reason a property fails.
#[derive(Clone, Debug)]
struct AnyValue(Value);

impl Arbitrary for AnyValue {
    fn arbitrary(g: &mut Gen) -> Self {
        AnyValue(value(g, 3))
    }
}

fn value(g: &mut Gen, depth: usize) -> Value {
    let containers = if depth == 0 { 0 } else { 3 };
    match u8::arbitrary(g) % (20 + containers) {
        0 => Value::Null,
        1 => Value::Undefined,
        2 => Value::Bool(bool::arbitrary(g)),
        3 => Value::Int8(i8::arbitrary(g)),
        4 => Value::UInt8(u8::arbitrary(g)),
        5 => Value::Int16(i16::arbitrary(g)),
        6 => Value::UInt16(u16::arbitrary(g)),
        7 => Value::Int32(i32::arbitrary(g)),
        8 => Value::UInt32(u32::arbitrary(g)),
        9 => Value::Int64(i64::arbitrary(g)),
        10 => Value::UInt64(u64::arbitrary(g)),
        11 => Value::Int128(i128::arbitrary(g)),
        12 => Value::UInt128(u128::arbitrary(g)),
        // Raw bit patterns, so NaN payloads and signaling NaNs are covered.
        13 => Value::Float32(f32::from_bits(u32::arbitrary(g))),
        14 => Value::Float64(f64::from_bits(u64::arbitrary(g))),
        15 => Value::String(String::arbitrary(g).into()),
        16 => Value::Bytes(Protected::new(Vec::arbitrary(g))),
        17 => date(g),
        18 => timestamp(g),
        19 => decimal(g),
        20 => Value::Array(
            (0..u8::arbitrary(g) % 4)
                .map(|_| value(g, depth - 1))
                .collect(),
        ),
        21 => {
            // The decoder rejects duplicate keys, so generate distinct ones.
            let mut keys: Vec<String> = Vec::arbitrary(g);
            keys.sort();
            keys.dedup();
            keys.truncate(4);
            Value::Object(keys.into_iter().map(|k| (k, value(g, depth - 1))).collect())
        }
        _ => Value::Passthrough(Box::new(value(g, depth - 1))),
    }
}

#[cfg(feature = "chrono")]
fn date(g: &mut Gen) -> Value {
    use chrono::Datelike;
    let (min, max) = (
        chrono::NaiveDate::MIN.num_days_from_ce(),
        chrono::NaiveDate::MAX.num_days_from_ce(),
    );
    let days = min + (u32::arbitrary(g) % (max - min) as u32) as i32;
    Value::Date(chrono::NaiveDate::from_num_days_from_ce_opt(days).expect("in range"))
}

#[cfg(feature = "chrono")]
fn timestamp(g: &mut Gen) -> Value {
    use chrono::DateTime;
    let (min, max) = (
        DateTime::<chrono::Utc>::MIN_UTC.timestamp(),
        DateTime::<chrono::Utc>::MAX_UTC.timestamp(),
    );
    let seconds = min + (u64::arbitrary(g) % (max - min) as u64) as i64;
    // Occasionally a leap second: nanoseconds >= 1e9 on second 59.
    let leap = u8::arbitrary(g) % 4 == 0;
    let (seconds, nanos) = if leap {
        (
            seconds - seconds.rem_euclid(60) + 59,
            1_000_000_000 + u32::arbitrary(g) % 1_000_000_000,
        )
    } else {
        (seconds, u32::arbitrary(g) % 1_000_000_000)
    };
    DateTime::from_timestamp(seconds, nanos)
        .map(Value::Timestamp)
        .unwrap_or(Value::Null)
}

#[cfg(feature = "rust_decimal")]
fn decimal(g: &mut Gen) -> Value {
    Value::Decimal(rust_decimal::Decimal::from_parts(
        u32::arbitrary(g),
        u32::arbitrary(g),
        u32::arbitrary(g),
        bool::arbitrary(g),
        u32::arbitrary(g) % 29,
    ))
}

#[cfg(not(feature = "chrono"))]
fn date(_: &mut Gen) -> Value {
    Value::Null
}

#[cfg(not(feature = "chrono"))]
fn timestamp(_: &mut Gen) -> Value {
    Value::Null
}

#[cfg(not(feature = "rust_decimal"))]
fn decimal(_: &mut Gen) -> Value {
    Value::Null
}

fn encode(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out).expect("generated values encode");
    out
}

/// Decode, and if the decoder accepts, require the exact bytes back.
fn accepted_input_is_canonical(bytes: &[u8]) -> bool {
    match decode_value(&mut Reader::new(bytes)) {
        Ok(value) => encode(value) == bytes,
        Err(_) => true,
    }
}

#[quickcheck]
fn every_value_round_trips(value: AnyValue) -> bool {
    let bytes = encode(value.0.clone());
    decode_value(&mut Reader::new(&bytes)).is_ok_and(|decoded| decoded == value.0)
}

#[quickcheck]
fn accepted_bytes_re_encode_exactly(bytes: Vec<u8>) -> bool {
    accepted_input_is_canonical(&bytes)
}

/// Random bytes rarely get past the first tag, so also start from a valid
/// encoding and corrupt it with one or two edits (overwrite, insert, delete
/// or truncate): most are refused, and the rest must still be canonical.
fn corrupted_encoding_is_refused_or_canonical(
    value: AnyValue,
    first: (u8, usize, u8),
    second: Option<(u8, usize, u8)>,
) -> bool {
    let mut bytes = encode(value.0);
    for (op, at, byte) in std::iter::once(first).chain(second) {
        let at = at % (bytes.len() + 1);
        match op % 4 {
            0 if at < bytes.len() => bytes[at] = byte,
            1 => bytes.insert(at, byte),
            2 if at < bytes.len() => {
                bytes.remove(at);
            }
            3 => bytes.truncate(at),
            _ => {}
        }
    }
    accepted_input_is_canonical(&bytes)
}

#[test]
fn corrupted_encodings_are_refused_or_canonical() {
    quickcheck::QuickCheck::new()
        .tests(1000)
        .quickcheck(corrupted_encoding_is_refused_or_canonical as fn(_, _, _) -> bool);
}
