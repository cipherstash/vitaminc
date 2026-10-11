//! Building a `Value` is just another sink.

use std::convert::Infallible;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead_value::Value;
use vitaminc_protected::Protected;

use crate::model::{MapSink, Plaintext, SeqSink, Sink};

pub struct ValueBuilder;

/// Snapshot any source as an owned `Value`.
pub fn to_value<P: Plaintext>(p: P) -> Value {
    match p.visit(ValueBuilder) {
        Ok(v) => v,
        Err(never) => match never {},
    }
}

macro_rules! scalar {
    ($($method:ident($ty:ty) => $variant:ident),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<Value, Infallible> {
                Ok(Value::$variant(v))
            }
        )*
    };
}

impl Sink for ValueBuilder {
    type Ok = Value;
    type Error = Infallible;
    type Seq = BuildSeq;
    type Map = BuildMap;

    fn null(self) -> Result<Value, Infallible> {
        Ok(Value::Null)
    }

    fn undefined(self) -> Result<Value, Infallible> {
        Ok(Value::Undefined)
    }

    scalar! {
        bool(bool) => Bool,
        i8(i8) => Int8, i16(i16) => Int16, i32(i32) => Int32, i64(i64) => Int64, i128(i128) => Int128,
        u8(u8) => UInt8, u16(u16) => UInt16, u32(u32) => UInt32, u64(u64) => UInt64, u128(u128) => UInt128,
        f32(f32) => Float32, f64(f64) => Float64,
        date(NaiveDate) => Date, timestamp(DateTime<Utc>) => Timestamp, decimal(Decimal) => Decimal,
    }

    fn str(self, v: &str) -> Result<Value, Infallible> {
        Ok(Value::String(v.into()))
    }

    fn bytes(self, v: &[u8]) -> Result<Value, Infallible> {
        Ok(Value::Bytes(Protected::new(v.to_vec())))
    }

    fn seq(self, len: usize) -> Result<BuildSeq, Infallible> {
        Ok(BuildSeq(Vec::with_capacity(len.min(1024))))
    }

    fn map(self, len: usize) -> Result<BuildMap, Infallible> {
        Ok(BuildMap(Vec::with_capacity(len.min(1024))))
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<Value, Infallible> {
        Ok(Value::Passthrough(Box::new(to_value(value))))
    }
}

pub struct BuildSeq(Vec<Value>);

impl SeqSink for BuildSeq {
    type Ok = Value;
    type Error = Infallible;

    fn element<P: Plaintext>(mut self, value: P) -> Result<Self, Infallible> {
        self.0.push(to_value(value));
        Ok(self)
    }

    fn end(self) -> Result<Value, Infallible> {
        Ok(Value::Array(self.0))
    }
}

pub struct BuildMap(Vec<(String, Value)>);

impl MapSink for BuildMap {
    type Ok = Value;
    type Error = Infallible;

    fn entry<P: Plaintext>(mut self, key: &str, value: P) -> Result<Self, Infallible> {
        self.0.push((key.to_owned(), to_value(value)));
        Ok(self)
    }

    fn end(self) -> Result<Value, Infallible> {
        Ok(Value::Object(self.0))
    }
}
