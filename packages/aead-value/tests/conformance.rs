#![cfg(all(feature = "chrono", feature = "rust_decimal"))]

use vitaminc_aead_value::{
    transport::{decode_value, encode_value, Reader},
    ValueKind,
};

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect()
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
        let mut encoded = Vec::new();
        encode_value(value, &mut encoded).expect("encode");
        assert_eq!(encoded, bytes, "{}", row["name"]);
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
