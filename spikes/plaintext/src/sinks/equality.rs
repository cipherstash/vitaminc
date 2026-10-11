//! Equality-term input as a sink: the canonical bytes a PRF would consume.
//!
//! This is the part the bytes-only `Cipher` data model can't do. The
//! encodings differ by type: a signed integer gets a sign byte that depends
//! on its value, an unsigned one always gets `1`. So the sink has to be told
//! "this is an i32" rather than handed four bytes.
//!
//! Output matches `canonical::equality_input(&Value)` exactly (tested).

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::canonical::{domain, equality_input, text_nfc, CanonicalError, EqualityInput};
use vitaminc_aead_value::{Value, ValueKind};
use vitaminc_protected::{Controlled, Protected};

use crate::model::{Impossible, Plaintext, Sink};

/// The equality input for one scalar. Containers, booleans, null and
/// passthrough have no term, as in `equality_input`.
pub struct EqualityTerm;

/// The canonical integer layout, written natively: sign byte, then the
/// value as a big-endian u128. Every width shares one domain.
fn integer(sign: u8, word: u128) -> EqualityInput {
    let word = Protected::new(word.to_be_bytes());
    let mut bytes = Protected::new(Vec::with_capacity(17));
    bytes.risky_inner_mut().push(sign);
    bytes.risky_inner_mut().extend_from_slice(word.risky_ref());
    EqualityInput {
        domain: domain::INTEGER,
        bytes,
    }
}

fn signed(v: i128) -> Result<EqualityInput, CanonicalError> {
    Ok(integer((!(v >> 127) & 1) as u8, v as u128))
}

fn unsigned(v: u128) -> Result<EqualityInput, CanonicalError> {
    Ok(integer(1, v))
}

/// SPIKE: the float, date, timestamp, decimal and bytes encodings are
/// private to aead-value's `canonical` module, which only exposes them
/// through `equality_input(&Value)`. So this builds a one-scalar `Value`
/// for them. With the encodings exposed per scalar this would go away.
fn via_value(v: Value) -> Result<EqualityInput, CanonicalError> {
    equality_input(&v)
}

impl Sink for EqualityTerm {
    type Ok = EqualityInput;
    type Error = CanonicalError;
    type Seq = Impossible<EqualityInput, CanonicalError>;
    type Map = Impossible<EqualityInput, CanonicalError>;

    fn null(self) -> Result<EqualityInput, CanonicalError> {
        Err(CanonicalError::UnsupportedValue)
    }

    fn undefined(self) -> Result<EqualityInput, CanonicalError> {
        Err(CanonicalError::UnsupportedValue)
    }

    fn bool(self, _: bool) -> Result<EqualityInput, CanonicalError> {
        Err(CanonicalError::UnsupportedKind(ValueKind::Bool))
    }

    fn i8(self, v: i8) -> Result<EqualityInput, CanonicalError> {
        signed(v.into())
    }

    fn i16(self, v: i16) -> Result<EqualityInput, CanonicalError> {
        signed(v.into())
    }

    fn i32(self, v: i32) -> Result<EqualityInput, CanonicalError> {
        signed(v.into())
    }

    fn i64(self, v: i64) -> Result<EqualityInput, CanonicalError> {
        signed(v.into())
    }

    fn i128(self, v: i128) -> Result<EqualityInput, CanonicalError> {
        signed(v)
    }

    fn u8(self, v: u8) -> Result<EqualityInput, CanonicalError> {
        unsigned(v.into())
    }

    fn u16(self, v: u16) -> Result<EqualityInput, CanonicalError> {
        unsigned(v.into())
    }

    fn u32(self, v: u32) -> Result<EqualityInput, CanonicalError> {
        unsigned(v.into())
    }

    fn u64(self, v: u64) -> Result<EqualityInput, CanonicalError> {
        unsigned(v.into())
    }

    fn u128(self, v: u128) -> Result<EqualityInput, CanonicalError> {
        unsigned(v)
    }

    fn f32(self, v: f32) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Float32(v))
    }

    fn f64(self, v: f64) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Float64(v))
    }

    fn date(self, v: NaiveDate) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Date(v))
    }

    fn timestamp(self, v: DateTime<Utc>) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Timestamp(v))
    }

    fn decimal(self, v: Decimal) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Decimal(v))
    }

    fn str(self, v: &str) -> Result<EqualityInput, CanonicalError> {
        Ok(EqualityInput {
            domain: domain::TEXT,
            bytes: text_nfc(v.as_bytes())?,
        })
    }

    fn bytes(self, v: &[u8]) -> Result<EqualityInput, CanonicalError> {
        via_value(Value::Bytes(Protected::new(v.to_vec())))
    }

    fn seq(self, _: usize) -> Result<Self::Seq, CanonicalError> {
        Err(CanonicalError::UnsupportedKind(ValueKind::Array))
    }

    fn map(self, _: usize) -> Result<Self::Map, CanonicalError> {
        Err(CanonicalError::UnsupportedKind(ValueKind::Object))
    }

    fn passthrough<P: Plaintext>(self, _: P) -> Result<EqualityInput, CanonicalError> {
        Err(CanonicalError::UnsupportedValue)
    }
}
