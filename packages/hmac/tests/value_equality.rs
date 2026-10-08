//! Vectors independently calculated with Python hashlib/hmac and explicit
//! big-endian canonical payloads; key = 0x0b * 32, empty context, PAE framing.
use vitaminc_aead_value::{canonical::equality_bytes, Value, ValueKind};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{CanonicalError, PrfEncoding, PrfError, PrfKeyInit, PrfValue};
use vitaminc_protected::{Controlled, Protected};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_equality_domain_has_a_known_answer() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    let vectors = [
        (
            Value::Int8(-7),
            "vitaminc/prf/value/int8-orderable/v1",
            "79",
            "45b646e792baac429bc9b0909bfee1f5d830340c2689dce4a157f7cd3f5c52f3",
        ),
        (
            Value::Int16(-7),
            "vitaminc/prf/value/int16-orderable/v1",
            "7ff9",
            "910b81e2c549234d1853e3d638b211586992e5ec46004f2d99d2287201dd6b64",
        ),
        (
            Value::Int32(-7),
            "vitaminc/prf/value/int32-orderable/v1",
            "7ffffff9",
            "c8e0b6c9ea09379eebe54ca54775961eedba9a140a60d5e1cb2a2e74e6971152",
        ),
        (
            Value::Int64(-7),
            "vitaminc/prf/value/int64-orderable/v1",
            "7ffffffffffffff9",
            "230a90e2b90dca97dcb96b6f8949fc481eac133c6009026a41b8d69c4df984a2",
        ),
        (
            Value::Int128(-7),
            "vitaminc/prf/value/int128-orderable/v1",
            "7ffffffffffffffffffffffffffffff9",
            "86ea7b332d238ddeaba562eb280075e1345eb9835f25a2ec0d4e239a9a341951",
        ),
        (
            Value::UInt8(7),
            "vitaminc/prf/value/uint8-orderable/v1",
            "07",
            "93bf0e77c1b9e2859c6307cea9a3c36a0eec73bc0930927bce0d147d627fab34",
        ),
        (
            Value::UInt16(7),
            "vitaminc/prf/value/uint16-orderable/v1",
            "0007",
            "75adfa1dd83181469e110035f65cc39710887aa9dbc674b5f9f938bd69934ddc",
        ),
        (
            Value::UInt32(7),
            "vitaminc/prf/value/uint32-orderable/v1",
            "00000007",
            "d1348bee44399b980d31a146f062a6398a4c12ac118d33a80fe4fede2c970e7c",
        ),
        (
            Value::UInt64(7),
            "vitaminc/prf/value/uint64-orderable/v1",
            "0000000000000007",
            "7fdc5f704d19e6a9dbcc43943379e4c7f6322146f2e78efd1799b130d772cda9",
        ),
        (
            Value::UInt128(7),
            "vitaminc/prf/value/uint128-orderable/v1",
            "00000000000000000000000000000007",
            "41d5f93103768546432733266bf168544b82cc329c97b91a96cf70a1db3e78d9",
        ),
        (
            Value::Float32(1.5),
            "vitaminc/prf/value/float32-orderable/v1",
            "bfc00000",
            "b14abcd83e1c53639315fae63c96b98d93cfec5793929ff37376dff64b3f73e9",
        ),
        (
            Value::Float64(-1.5),
            "vitaminc/prf/value/float64-orderable/v1",
            "4007ffffffffffff",
            "e31d40623c1470970496696ec78f168e100d0404e5e5f1da83b9d5d01402e48a",
        ),
        (
            Value::Date(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()),
            "vitaminc/prf/value/date-orderable/v1",
            "800af93b",
            "57720e5c53bfa2e7e83b04faf4f740927c2ffd6f87f84fa32a91e709a71c83f4",
        ),
        (
            Value::Timestamp(chrono::DateTime::from_timestamp(-1, 999_999_999).unwrap()),
            "vitaminc/prf/value/timestamp-micros-orderable/v1",
            "7fffffffffffffff3b9ac618",
            "9fc40c1a26ed4aed4bd73402040bcd8da02b4665509c99ac5a4edd5bee9ac57f",
        ),
        (
            Value::Decimal("1.00".parse().unwrap()),
            "vitaminc/prf/value/decimal-orderable/v1",
            "c000204fce5e3e25026110000000",
            "4a2d2091d09c610d416209925d3ac31b12a34d06d0771539a55065e46a542dc3",
        ),
        (
            Value::String("e\u{301}".into()),
            "vitaminc/prf/value/text-nfc/unicode-16/v1",
            "c3a9",
            "b1bd0d5919b11845e2b4e1df2dd74a0fe7dddc7505a4bec84883393564bf64a7",
        ),
        (
            Value::Bytes(Protected::new(vec![0, 255, 7])),
            "vitaminc/prf/value/bytes/v1",
            "00ff07",
            "39bb4ddca2af43c8afb23184af6a3baab6c5a3a0dc420d78700abc2e37abc36d",
        ),
    ];
    let mut covered = Vec::new();
    for (value, domain, payload, expected) in vectors {
        let kind = value.kind().unwrap();
        covered.push(kind);
        assert_eq!(PrfEncoding::for_value_kind(kind).unwrap().as_str(), domain);
        assert_eq!(
            hex(equality_bytes(&value).unwrap().risky_ref()),
            payload,
            "{kind}"
        );
        assert_eq!(
            hex(&(&value).prf(&prf).into_result().unwrap()),
            expected,
            "{kind}"
        );
        assert_ne!(
            (&value)
                .prf_with_context(&prf, ("tenant", 1u64))
                .into_result()
                .unwrap(),
            (&value)
                .prf_with_context(&prf, ("tenant", 2u64))
                .into_result()
                .unwrap(),
        );
    }
    let exceptions = [ValueKind::Bool, ValueKind::Array, ValueKind::Object];
    for &kind in ValueKind::ALL {
        assert_eq!(
            covered.contains(&kind),
            !exceptions.contains(&kind),
            "{kind}"
        );
        assert_eq!(
            PrfEncoding::for_value_kind(kind).is_some(),
            covered.contains(&kind)
        );
    }
}

#[test]
fn unsupported_values_return_typed_errors_without_hashing() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    assert!(matches!(
        (&Value::Bool(true)).prf(&prf).into_result(),
        Err(PrfError::Canonical(CanonicalError::UnsupportedKind(
            ValueKind::Bool
        )))
    ));
    assert!(matches!(
        (&Value::String("\u{378}".into())).prf(&prf).into_result(),
        Err(PrfError::Canonical(CanonicalError::UnassignedCodePoint))
    ));
}

#[test]
fn canonical_equivalence_preserves_source_and_legacy_domains() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    let source = Value::String("e\u{301}".into());
    let equivalent = Value::String("é".into());
    assert_eq!(
        (&source).prf(&prf).into_result().unwrap(),
        (&equivalent).prf(&prf).into_result().unwrap()
    );
    match source {
        Value::String(text) => assert_eq!(text.risky_ref(), "e\u{301}".as_bytes()),
        _ => unreachable!(),
    }
    assert_ne!(
        (&Value::Int64(7)).prf(&prf).into_result().unwrap(),
        7i64.prf(&prf).into_result().unwrap()
    );
}
