#![cfg(all(feature = "chrono", feature = "rust_decimal"))]

use vitaminc_aead_value::{
    transport::{decode_value, encode_value, Reader},
    Value, ValueKind,
};
use vitaminc_protected::{Controlled, Protected};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect()
}

/// The value a vector's `kind` and `value` fields describe, built with
/// std, chrono and rust_decimal parsers rather than the transport decoder,
/// so a bug that decodes and encodes symmetrically wrong cannot pass.
fn expected(kind: &str, value: &serde_json::Value) -> Value {
    fn int<T: std::str::FromStr>(value: &serde_json::Value) -> T {
        let text = value.as_str().expect("integers are JSON strings");
        text.parse()
            .unwrap_or_else(|_| panic!("{text} is out of range"))
    }
    let text = || value.as_str().expect("JSON string");
    match kind {
        "null" => Value::Null,
        "undefined" => Value::Undefined,
        "bool" => Value::Bool(value.as_bool().expect("JSON bool")),
        "int8" => Value::Int8(int(value)),
        "uint8" => Value::UInt8(int(value)),
        "int16" => Value::Int16(int(value)),
        "uint16" => Value::UInt16(int(value)),
        "int32" => Value::Int32(int(value)),
        "uint32" => Value::UInt32(int(value)),
        "int64" => Value::Int64(int(value)),
        "uint64" => Value::UInt64(int(value)),
        "int128" => Value::Int128(int(value)),
        "uint128" => Value::UInt128(int(value)),
        "float32" => Value::Float32(value.as_f64().expect("JSON number") as f32),
        "float64" => Value::Float64(value.as_f64().expect("JSON number")),
        "string" => Value::String(text().into()),
        "bytes" => Value::Bytes(Protected::new(unhex(text()))),
        "date" => {
            Value::Date(chrono::NaiveDate::parse_from_str(text(), "%Y-%m-%d").expect("valid date"))
        }
        "timestamp" => Value::Timestamp(text().parse().expect("valid timestamp")),
        "decimal" => {
            let mut decimal = rust_decimal::Decimal::from_str_exact(text()).expect("valid decimal");
            // Parsing drops the sign of zero; the wire format keeps it.
            decimal.set_sign_negative(text().starts_with('-'));
            Value::Decimal(decimal)
        }
        "array" if value.as_array().is_some_and(Vec::is_empty) => Value::Array(vec![]),
        "object" if value.as_object().is_some_and(|map| map.is_empty()) => Value::Object(vec![]),
        _ => panic!("teach expected() the {kind} vector {value}"),
    }
}

/// Structural equality for the scalar shapes the corpus holds. `Value`'s
/// own `PartialEq` is crate-test-only, so compare here. Floats compare by bit
/// pattern and decimals by their serialized form, which includes scale.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) | (Value::Undefined, Value::Undefined) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Int8(a), Value::Int8(b)) => a == b,
        (Value::UInt8(a), Value::UInt8(b)) => a == b,
        (Value::Int16(a), Value::Int16(b)) => a == b,
        (Value::UInt16(a), Value::UInt16(b)) => a == b,
        (Value::Int32(a), Value::Int32(b)) => a == b,
        (Value::UInt32(a), Value::UInt32(b)) => a == b,
        (Value::Int64(a), Value::Int64(b)) => a == b,
        (Value::UInt64(a), Value::UInt64(b)) => a == b,
        (Value::Int128(a), Value::Int128(b)) => a == b,
        (Value::UInt128(a), Value::UInt128(b)) => a == b,
        (Value::Float32(a), Value::Float32(b)) => a.to_bits() == b.to_bits(),
        (Value::Float64(a), Value::Float64(b)) => a.to_bits() == b.to_bits(),
        (Value::String(a), Value::String(b)) => a.risky_ref() == b.risky_ref(),
        (Value::Bytes(a), Value::Bytes(b)) => a.risky_ref() == b.risky_ref(),
        (Value::Date(a), Value::Date(b)) => a == b,
        (Value::Timestamp(a), Value::Timestamp(b)) => a == b,
        (Value::Decimal(a), Value::Decimal(b)) => a.serialize() == b.serialize(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ka, va), (kb, vb))| ka == kb && same(va, vb))
        }
        _ => false,
    }
}

#[test]
fn shared_binding_corpus_covers_every_tag_and_kind() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/value-conformance.json"))
            .expect("corpus JSON");
    let mut tags = Vec::new();
    let mut kinds = Vec::new();
    for row in corpus["vectors"].as_array().expect("vectors") {
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        tags.push(bytes[0]);
        let value = decode_value(&mut Reader::new(&bytes)).expect("valid vector");
        if let Some(kind) = value.kind() {
            kinds.push(kind);
        }
        let want = expected(row["kind"].as_str().expect("kind"), &row["value"]);
        assert!(
            same(&value, &want),
            "{}: decoded value differs from `value`",
            row["name"]
        );
        let mut encoded = Vec::new();
        encode_value(value, &mut encoded).expect("encode");
        assert_eq!(encoded, bytes, "{}", row["name"]);
        // Encode from the independently built value too, not only the decoded one.
        let mut from_expected = Vec::new();
        encode_value(want, &mut from_expected).expect("encode");
        assert_eq!(from_expected, bytes, "{}", row["name"]);
    }
    for tag in 0x00..=0x14 {
        assert!(tags.contains(&tag), "missing scalar tag {tag:02x}");
    }
    for kind in ValueKind::ALL {
        assert!(kinds.contains(kind), "missing kind {kind}");
    }
    for row in corpus["malformed"].as_array().expect("malformed") {
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        assert!(
            decode_value(&mut Reader::new(&bytes)).is_err(),
            "{}",
            row["name"]
        );
    }
}
