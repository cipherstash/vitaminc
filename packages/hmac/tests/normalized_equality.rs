//! Vectors independently calculated with Python hashlib/hmac and explicit
//! big-endian normalized payloads; key = 0x0b * 32, empty context, PAE
//! framing. They are the vectors the `&Value` path produced before
//! normalization moved into `vitaminc-normalize`, so the PRF output over a
//! `Normalized` term is pinned to what it was. Every integer width shares
//! one domain and payload, so each width carries the same vector for the
//! same number; both float widths likewise share one domain, with `f32`
//! widened exactly to `f64`.
use vitaminc_aead::plaintext::kinds::chrono as conv;
use vitaminc_aead::{Float, Int, Logical, Physical, TimeUnit};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_normalize::{domain, normalize};
use vitaminc_prf::{EqualityTerm, NormalizeError, PrfError, PrfKeyInit, PrfValue};
use vitaminc_protected::{Controlled, Protected};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn every_equality_domain_has_a_known_answer() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    let minus_seven = (
        domain::INTEGER,
        "00fffffffffffffffffffffffffffffff9",
        "e025b480a9b3b10b709056fd6fc5ec4ca44c04476d4ebed8360110fec3a0e511",
    );
    let seven = (
        domain::INTEGER,
        "0100000000000000000000000000000007",
        "8e9c7310e99f566c03e43de34c13cd21fe0e3fc6fb03cf7a6c2f31b86e336a5a",
    );
    let epoch = conv::date_days(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("date"));
    let before_epoch = conv::timestamp_nanos(
        chrono::DateTime::from_timestamp(-1, 999_999_999).expect("timestamp"),
    )
    .expect("not a leap second");
    let one: rust_decimal::Decimal = "1.00".parse().expect("decimal");
    let uuid = uuid::Uuid::from_bytes([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ]);
    let vectors = [
        ((None, Physical::Int(Int::I8(-7))), minus_seven),
        ((None, Physical::Int(Int::I16(-7))), minus_seven),
        ((None, Physical::Int(Int::I32(-7))), minus_seven),
        ((None, Physical::Int(Int::I64(-7))), minus_seven),
        ((None, Physical::Int(Int::I128(-7))), minus_seven),
        ((None, Physical::Int(Int::U8(7))), seven),
        ((None, Physical::Int(Int::U16(7))), seven),
        ((None, Physical::Int(Int::U32(7))), seven),
        ((None, Physical::Int(Int::U64(7))), seven),
        ((None, Physical::Int(Int::U128(7))), seven),
        (
            (None, Physical::Float(Float::F32(1.5))),
            (
                domain::FLOAT,
                "bff8000000000000",
                "8a4e5233cd0f982178536465a0ced2b2d3451198a57da553970a17a0069be1e1",
            ),
        ),
        (
            (None, Physical::Float(Float::F64(-1.5))),
            (
                domain::FLOAT,
                "4007ffffffffffff",
                "cf40d5d1d3da65f02bb0ceaabebce6c2569a129cb890e19a9b4dbacefb763adb",
            ),
        ),
        (
            (Some(Logical::Date), Physical::Int(Int::I32(epoch))),
            (
                domain::DATE,
                "800af93b",
                "57720e5c53bfa2e7e83b04faf4f740927c2ffd6f87f84fa32a91e709a71c83f4",
            ),
        ),
        (
            (
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(before_epoch)),
            ),
            (
                domain::TIMESTAMP,
                "7fffffffffffffff3b9ac618",
                "9fc40c1a26ed4aed4bd73402040bcd8da02b4665509c99ac5a4edd5bee9ac57f",
            ),
        ),
        (
            (
                Some(Logical::Decimal {
                    scale: one.scale() as u8,
                }),
                Physical::Int(Int::I128(one.mantissa())),
            ),
            (
                domain::DECIMAL,
                "c000204fce5e3e25026110000000",
                "4a2d2091d09c610d416209925d3ac31b12a34d06d0771539a55065e46a542dc3",
            ),
        ),
        (
            (None, Physical::Text("e\u{301}")),
            (
                domain::TEXT,
                "c3a9",
                "b1bd0d5919b11845e2b4e1df2dd74a0fe7dddc7505a4bec84883393564bf64a7",
            ),
        ),
        (
            (None, Physical::Bytes(&[0, 255, 7])),
            (
                domain::BYTES,
                "00ff07",
                "39bb4ddca2af43c8afb23184af6a3baab6c5a3a0dc420d78700abc2e37abc36d",
            ),
        ),
        (
            (Some(Logical::Uuid), Physical::Bytes(uuid.as_bytes())),
            (
                domain::UUID,
                "123456789abcdef0123456789abcdef0",
                "212c08cbe7d388777e819e618a0d2b0f529c5b268c3a3e9682dd380ae6da0a56",
            ),
        ),
    ];
    let mut covered = Vec::new();
    for ((ty, value), (expected_domain, payload, expected)) in vectors {
        let scalar = EqualityTerm::new(ty, value);
        let term = normalize(ty, value).expect("has a term");
        assert_eq!(term.domain, expected_domain);
        assert_eq!(hex(term.bytes.risky_ref()), payload, "{expected_domain}");
        // The term and the scalar it came from derive the same block, and
        // the borrowed term derives under the context it is given.
        let block = scalar.prf(&prf).into_result().expect("derives");
        assert_eq!(hex(&block), expected, "{expected_domain}");
        assert_eq!((&term).prf(&prf).into_result().expect("derives"), block);
        assert_eq!(
            (&term)
                .prf_with_context(&prf, ("tenant", 1u64))
                .into_result()
                .expect("derives"),
            scalar
                .prf_with_context(&prf, ("tenant", 1u64))
                .into_result()
                .expect("derives"),
        );
        assert_eq!(term.prf(&prf).into_result().expect("derives"), block);
        assert_ne!(
            scalar
                .prf_with_context(&prf, ("tenant", 1u64))
                .into_result()
                .expect("derives"),
            scalar
                .prf_with_context(&prf, ("tenant", 2u64))
                .into_result()
                .expect("derives"),
        );
        covered.push(expected_domain);
    }
    // Every domain the normalizer knows has a vector above, and the labels
    // themselves are pinned, not only through the HMAC outputs.
    for domain in domain::ALL {
        assert!(covered.contains(domain), "{domain}");
    }
    assert_eq!(
        domain::ALL,
        [
            "vitaminc/prf/value/integer-orderable/v1",
            "vitaminc/prf/value/float-orderable/v1",
            "vitaminc/prf/value/date-orderable/v1",
            "vitaminc/prf/value/timestamp-micros-orderable/v1",
            "vitaminc/prf/value/decimal-orderable/v1",
            "vitaminc/prf/value/text-nfc/unicode-16/v1",
            "vitaminc/prf/value/bytes/v1",
            "vitaminc/prf/value/uuid/v1",
        ]
    );
}

#[test]
fn unsupported_values_return_typed_errors_without_hashing() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    assert!(matches!(
        EqualityTerm::new(None, Physical::Bool(true))
            .prf(&prf)
            .into_result(),
        Err(PrfError::Normalize(NormalizeError::NoDomain))
    ));
    assert!(matches!(
        EqualityTerm::new(None, Physical::Null)
            .prf(&prf)
            .into_result(),
        Err(PrfError::Normalize(NormalizeError::NoDomain))
    ));
    assert!(matches!(
        EqualityTerm::new(None, Physical::Text("\u{378}"))
            .prf(&prf)
            .into_result(),
        Err(PrfError::Normalize(NormalizeError::UnassignedCodePoint))
    ));
    assert!(matches!(
        EqualityTerm::new(Some(Logical::Date), Physical::Text("1970-01-01"))
            .prf(&prf)
            .into_result(),
        Err(PrfError::Normalize(NormalizeError::Invalid))
    ));
}

#[test]
fn normalized_equivalence_keeps_the_legacy_domains_apart() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    assert_eq!(
        EqualityTerm::new(None, Physical::Text("e\u{301}"))
            .prf(&prf)
            .into_result()
            .expect("derives"),
        EqualityTerm::new(None, Physical::Text("é"))
            .prf(&prf)
            .into_result()
            .expect("derives")
    );
    // The built-in `i64` encoding keeps its own domain; the equality term
    // for the same number is under the integer domain.
    assert_ne!(
        EqualityTerm::new(None, Physical::Int(Int::I64(7)))
            .prf(&prf)
            .into_result()
            .expect("derives"),
        7i64.prf(&prf).into_result().expect("derives")
    );
    // A date is not its day count, and a uuid is not its bytes.
    assert_ne!(
        EqualityTerm::new(Some(Logical::Date), Physical::Int(Int::I32(0)))
            .prf(&prf)
            .into_result()
            .expect("derives"),
        EqualityTerm::new(None, Physical::Int(Int::I32(0)))
            .prf(&prf)
            .into_result()
            .expect("derives")
    );
    let id = [5u8; 16];
    assert_ne!(
        EqualityTerm::new(Some(Logical::Uuid), Physical::Bytes(&id))
            .prf(&prf)
            .into_result()
            .expect("derives"),
        EqualityTerm::new(None, Physical::Bytes(&id))
            .prf(&prf)
            .into_result()
            .expect("derives")
    );
}

/// A term that fails to normalize inside a container fails the whole
/// derivation: the container driver keeps the first child error, so a
/// caller never gets fewer terms than it gave with no error.
#[test]
fn a_normalize_error_inside_a_container_fails_the_whole_derivation() {
    let prf = HmacSha256Prf::new(Protected::new([0x0b; 32]));
    let terms = vec![
        EqualityTerm::new(None, Physical::Int(Int::I64(7))),
        EqualityTerm::new(None, Physical::Bool(true)),
    ];
    assert!(matches!(
        terms.prf(&prf).into_result(),
        Err(PrfError::Normalize(NormalizeError::NoDomain))
    ));
    let mut fields = std::collections::BTreeMap::new();
    let joined = EqualityTerm::new(Some(Logical::Date), Physical::Text("1970-01-01"));
    fields.insert("joined", joined);
    assert!(matches!(
        fields.prf(&prf).into_result(),
        Err(PrfError::Normalize(NormalizeError::Invalid))
    ));
    assert!(matches!(
        Some(EqualityTerm::new(None, Physical::Null))
            .prf(&prf)
            .into_result(),
        Err(PrfError::Normalize(NormalizeError::NoDomain))
    ));
}
