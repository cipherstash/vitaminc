//! `Value` as one source among several, the way `serde_json::Value`
//! implements `Serialize`. Nothing downstream needs it any more; it is only
//! useful when a caller wants an owned, `Send` snapshot.

use vitaminc_aead_value::Value;
use vitaminc_protected::Controlled;

use crate::model::{MapSink, Plaintext, SeqSink, Sink};

impl Plaintext for &Value {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => sink.null(),
            Value::Undefined => sink.undefined(),
            Value::Bool(v) => sink.bool(*v),
            Value::Int8(v) => sink.i8(*v),
            Value::Int16(v) => sink.i16(*v),
            Value::Int32(v) => sink.i32(*v),
            Value::Int64(v) => sink.i64(*v),
            Value::Int128(v) => sink.i128(*v),
            Value::UInt8(v) => sink.u8(*v),
            Value::UInt16(v) => sink.u16(*v),
            Value::UInt32(v) => sink.u32(*v),
            Value::UInt64(v) => sink.u64(*v),
            Value::UInt128(v) => sink.u128(*v),
            Value::Float32(v) => sink.f32(*v),
            Value::Float64(v) => sink.f64(*v),
            Value::Date(v) => sink.date(*v),
            Value::Timestamp(v) => sink.timestamp(*v),
            Value::Decimal(v) => sink.decimal(*v),
            Value::String(s) => {
                // Utf8String only holds valid UTF-8 (every constructor checks).
                let text = std::str::from_utf8(s.risky_ref()).expect("Utf8String invariant");
                sink.str(text)
            }
            Value::Bytes(b) => sink.bytes(b.risky_ref()),
            Value::Array(items) => items
                .iter()
                .try_fold(sink.seq(items.len())?, SeqSink::element)?
                .end(),
            Value::Object(entries) => entries
                .iter()
                .try_fold(sink.map(entries.len())?, |map, (k, v)| map.entry(k, v))?
                .end(),
            Value::Passthrough(inner) => sink.passthrough(&**inner),
            // SPIKE: `Value` is `#[non_exhaustive]` and this impl lives outside
            // its crate, so a wildcard is forced on us. In aead-value itself
            // this match would be exhaustive and the arm would go away. Every
            // downstream crate would implement `Sink` instead, which has no
            // wildcard to fall into.
            _ => unreachable!("a Value kind this spike doesn't know about"),
        }
    }
}

impl Plaintext for Value {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        // Borrow, then let `self` drop and wipe its protected leaves.
        (&self).visit(sink)
    }
}
