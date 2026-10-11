#![allow(dead_code)]

use chrono::{DateTime, NaiveDate, Utc};
use vitaminc_aead_value::transport::{decode_value, encode_value, Reader};
use vitaminc_aead_value::Value;
use vitaminc_protected::Protected;

pub struct Vector {
    pub name: String,
    pub bytes: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vectors(section: &str) -> Vec<Vector> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../../testdata/value-conformance.json")).expect("corpus");
    corpus[section]
        .as_array()
        .expect("section")
        .iter()
        .map(|v| Vector {
            name: v["name"].as_str().expect("name").to_owned(),
            bytes: hex(v["transport"].as_str().expect("transport")),
        })
        .collect()
}

/// Every valid corpus vector, plus a nested sample that covers containers
/// and passthrough.
pub fn valid() -> Vec<Vector> {
    let mut all = vectors("vectors");
    all.push(Vector {
        name: "nested-sample".into(),
        bytes: encode(sample()),
    });
    all
}

pub fn malformed() -> Vec<Vector> {
    vectors("malformed")
}

pub fn decode(bytes: &[u8]) -> Value {
    decode_value(&mut Reader::new(bytes)).expect("decodes")
}

pub fn encode(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out).expect("encodes");
    out
}

pub fn ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("valid")
}

pub fn sample() -> Value {
    Value::Object(vec![
        ("name".into(), Value::String("Ada".into())),
        ("age".into(), Value::UInt32(34)),
        (
            "scores".into(),
            Value::Array(vec![Value::Int8(-1), Value::Float64(2.5), Value::Null]),
        ),
        (
            "joined".into(),
            Value::Date(NaiveDate::from_ymd_opt(2024, 2, 29).expect("valid")),
        ),
        ("note".into(), Value::Passthrough(Box::new(Value::String("public".into())))),
        ("blob".into(), Value::Bytes(Protected::new(vec![1, 2, 3]))),
        ("seen".into(), Value::Timestamp(ts())),
        ("active".into(), Value::Bool(true)),
    ])
}
