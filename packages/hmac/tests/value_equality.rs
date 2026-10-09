//! Vectors independently calculated with Python hashlib/hmac and explicit
//! big-endian canonical payloads; key = 0x0b * 32, empty context, PAE framing.
//! Every integer width shares one domain and payload, so each integer kind
//! carries the same vector for the same number; both float widths likewise
//! share one domain, with float32 widened exactly to float64.
use vitaminc_aead_value::{canonical::equality_input, Value, ValueKind};
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
            "vitaminc/prf/value/integer-orderable/v1",
            "00fffffffffffffffffffffffffffffff9",
            "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
        ),
        (
            Value::Int16(-7),
            "vitaminc/prf/value/integer-orderable/v1",
            "00fffffffffffffffffffffffffffffff9",
            "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
        ),
        (
            Value::Int32(-7),
            "vitaminc/prf/value/integer-orderable/v1",
            "00fffffffffffffffffffffffffffffff9",
            "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
        ),
        (
            Value::Int64(-7),
            "vitaminc/prf/value/integer-orderable/v1",
            "00fffffffffffffffffffffffffffffff9",
            "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
        ),
        (
            Value::Int128(-7),
            "vitaminc/prf/value/integer-orderable/v1",
            "00fffffffffffffffffffffffffffffff9",
            "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
        ),
        (
            Value::UInt8(7),
            "vitaminc/prf/value/integer-orderable/v1",
            "0100000000000000000000000000000007",
            "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
        ),
        (
            Value::UInt16(7),
            "vitaminc/prf/value/integer-orderable/v1",
            "0100000000000000000000000000000007",
            "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
        ),
        (
            Value::UInt32(7),
            "vitaminc/prf/value/integer-orderable/v1",
            "0100000000000000000000000000000007",
            "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
        ),
        (
            Value::UInt64(7),
            "vitaminc/prf/value/integer-orderable/v1",
            "0100000000000000000000000000000007",
            "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
        ),
        (
            Value::UInt128(7),
            "vitaminc/prf/value/integer-orderable/v1",
            "0100000000000000000000000000000007",
            "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
        ),
        (
            Value::Float32(1.5),
            "vitaminc/prf/value/float-orderable/v1",
            "bff8000000000000",
            "8a4e5233cd0f982178536465a0ced2b2d3451198a57da553970a17a0069be1e1",
        ),
        (
            Value::Float64(-1.5),
            "vitaminc/prf/value/float-orderable/v1",
            "4007ffffffffffff",
            "cf40d5d1d3da65f02bb0ceaabebce6c2569a129cb890e19a9b4dbacefb763adb",
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
            hex(equality_input(&value).unwrap().bytes.risky_ref()),
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
