//! Equality terms for the language-neutral value model.

use vitaminc_aead_value::{
    canonical::{equality_domain, equality_input, EqualityInput},
    Value, ValueKind,
};

use crate::{IntoPrfContext, Prf, PrfEncoding, PrfError, PrfValue, PrfVisitor};

impl PrfEncoding {
    /// The canonical equality domain for a value kind. Every integer kind
    /// shares one domain. Legacy primitive `PrfValue` encodings retain their
    /// existing domains and bytes.
    pub const fn for_value_kind(kind: ValueKind) -> Option<Self> {
        match equality_domain(kind) {
            Some(domain) => Some(Self::new(domain)),
            None => None,
        }
    }
}

impl PrfValue for &Value {
    fn prf_visit_with_context<'a, P, V, C>(self, prf: &P, context: C, visitor: V) -> P::Ok<V::Value>
    where
        P: Prf,
        V: PrfVisitor<P::Block, P::Passthrough>,
        C: IntoPrfContext<'a>,
    {
        // The exhaustive Value dispatch lives in the shared canonical layer,
        // inside Value's crate, where non_exhaustive cannot hide a new kind.
        // It returns each term's domain with its bytes.
        match equality_input(self) {
            Ok(EqualityInput { domain, bytes }) => prf.prf_bytes_vec(
                bytes,
                PrfEncoding::new(domain),
                context.into_prf_context().into_owned(),
                visitor,
            ),
            Err(error) => prf.failure(PrfError::Canonical(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_backend::MockPrf, CanonicalError};

    #[test]
    fn value_domains_are_frozen_and_complete() {
        let expected = [
            (ValueKind::Int8, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::UInt8, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::Int16, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::UInt16, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::Int32, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::UInt32, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::Int64, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::UInt64, "vitaminc/prf/value/integer-orderable/v1"),
            (ValueKind::Int128, "vitaminc/prf/value/integer-orderable/v1"),
            (
                ValueKind::UInt128,
                "vitaminc/prf/value/integer-orderable/v1",
            ),
            (ValueKind::Float32, "vitaminc/prf/value/float-orderable/v1"),
            (ValueKind::Float64, "vitaminc/prf/value/float-orderable/v1"),
            (ValueKind::Date, "vitaminc/prf/value/date-orderable/v1"),
            (
                ValueKind::Timestamp,
                "vitaminc/prf/value/timestamp-micros-orderable/v1",
            ),
            (
                ValueKind::Decimal,
                "vitaminc/prf/value/decimal-orderable/v1",
            ),
            (
                ValueKind::String,
                "vitaminc/prf/value/text-nfc/unicode-16/v1",
            ),
            (ValueKind::Bytes, "vitaminc/prf/value/bytes/v1"),
        ];
        for (kind, label) in expected {
            assert_eq!(PrfEncoding::for_value_kind(kind).unwrap().as_str(), label);
        }
        for &kind in ValueKind::ALL {
            assert_eq!(
                PrfEncoding::for_value_kind(kind).is_some(),
                expected.iter().any(|(supported, _)| *supported == kind)
            );
        }
    }

    #[test]
    fn borrowed_value_dispatches_canonical_bytes_and_context() {
        let backend = MockPrf;
        let source = Value::String("e\u{301}".into());
        let equivalent = Value::String("é".into());
        assert_eq!(
            (&source).prf(&backend).into_result().unwrap(),
            (&equivalent).prf(&backend).into_result().unwrap()
        );
        assert_ne!(
            (&source)
                .prf_with_context(&backend, ("tenant", 1u64))
                .into_result()
                .unwrap(),
            (&source)
                .prf_with_context(&backend, ("tenant", 2u64))
                .into_result()
                .unwrap()
        );
        assert!(matches!(
            (&Value::Bool(false)).prf(&backend).into_result(),
            Err(PrfError::Canonical(CanonicalError::UnsupportedKind(
                ValueKind::Bool
            )))
        ));
        assert!(matches!(
            (&Value::String("\u{378}".into()))
                .prf(&backend)
                .into_result(),
            Err(PrfError::Canonical(CanonicalError::UnassignedCodePoint))
        ));
    }
}
