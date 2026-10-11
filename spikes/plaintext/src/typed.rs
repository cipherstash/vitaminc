//! Statically typed decryption as sinks: the replacement for `Decrypt`.
//!
//! A scalar target is one function from a scalar (logical plus physical) to
//! the type, or `None` to refuse it. Containers push into the parent. A
//! `#[derive(Decode)]` would generate the struct case.
//!
//! Integer targets read the value, not the width: a `u32` accepts an `i8`
//! leaf holding 34 and refuses one holding -1. Width is a host-fidelity hint.

use std::marker::PhantomData;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::IntoAad;

use crate::decrypt::{decrypt_into, DecryptError};
use crate::encrypt::{Backend, Node};
use crate::kinds::{self, Float, Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::sources::Uuid;

#[derive(Debug)]
pub enum DecodeError {
    /// The ciphertext holds something other than the target type.
    Expected(&'static str),
    Source(SourceError),
}

impl Error for DecodeError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

pub trait Decode: Sized {
    type Sink: Sink<Ok = Self, Error = DecodeError>;
    fn sink() -> Self::Sink;
}

pub fn decrypt_as<'a, T, B, A>(backend: &B, node: Node<B::Leaf>, aad: A) -> Result<T, DecryptError<DecodeError>>
where
    T: Decode,
    B: Backend,
    A: IntoAad<'a>,
{
    decrypt_into(backend, node, aad, T::sink())
}

/// A type that decodes from one scalar.
pub trait FromScalar: Sized {
    const EXPECTED: &'static str;
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self>;
}

pub struct ScalarSink<T>(PhantomData<T>);

impl<T: FromScalar> Sink for ScalarSink<T> {
    type Ok = T;
    type Error = DecodeError;
    type Seq = Never<T>;
    type Map = Never<T>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<T, DecodeError> {
        T::from_scalar(ty, v).ok_or(DecodeError::Expected(T::EXPECTED))
    }

    fn seq(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn map(self, _: Option<usize>) -> Result<Never<T>, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }

    fn passthrough<P: Plaintext>(self, _: P) -> Result<T, DecodeError> {
        Err(DecodeError::Expected(T::EXPECTED))
    }
}

macro_rules! decode_scalar {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Decode for $ty {
                type Sink = ScalarSink<$ty>;
                fn sink() -> Self::Sink {
                    ScalarSink(PhantomData)
                }
            }
        )*
    };
}

macro_rules! int_target {
    ($($ty:ty),* $(,)?) => {
        $(
            impl FromScalar for $ty {
                const EXPECTED: &'static str = stringify!($ty);
                fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
                    match (ty, v) {
                        (None, Physical::Int(i)) => i
                            .to_i128()
                            .and_then(|v| Self::try_from(v).ok())
                            .or_else(|| i.to_u128().and_then(|v| Self::try_from(v).ok())),
                        _ => None,
                    }
                }
            }
        )*
        decode_scalar!($($ty),*);
    };
}

int_target!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);

impl FromScalar for bool {
    const EXPECTED: &'static str = "bool";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Bool(b)) => Some(b),
            _ => None,
        }
    }
}

impl FromScalar for f64 {
    const EXPECTED: &'static str = "f64";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Float(Float::F64(f))) => Some(f),
            (None, Physical::Float(Float::F32(f))) => Some(f.into()),
            _ => None,
        }
    }
}

impl FromScalar for String {
    const EXPECTED: &'static str = "string";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (None, Physical::Text(s)) => Some(s.to_owned()),
            _ => None,
        }
    }
}

impl FromScalar for NaiveDate {
    const EXPECTED: &'static str = "date";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Date), Physical::Int(days)) => kinds::date(days),
            _ => None,
        }
    }
}

/// Any unit: a JS `Date` (milliseconds) decodes as well as a Rust one.
impl FromScalar for DateTime<Utc> {
    const EXPECTED: &'static str = "timestamp";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Timestamp(unit)), Physical::Int(count)) => kinds::timestamp(unit, count),
            _ => None,
        }
    }
}

impl FromScalar for Decimal {
    const EXPECTED: &'static str = "decimal";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => kinds::decimal(scale, mantissa),
            _ => None,
        }
    }
}

impl FromScalar for Uuid {
    const EXPECTED: &'static str = "uuid";
    fn from_scalar(ty: Option<Logical>, v: Physical<'_>) -> Option<Self> {
        match (ty, v) {
            (Some(Logical::Uuid), Physical::Bytes(b)) => b.try_into().ok().map(Uuid),
            _ => None,
        }
    }
}

decode_scalar!(bool, f64, String, NaiveDate, DateTime<Utc>, Decimal, Uuid);

/// Container sinks for a scalar target. Never built: `seq`/`map` refuse.
pub enum Never<T> {
    _Never(std::convert::Infallible, PhantomData<T>),
}

impl<T> SeqSink for Never<T> {
    type Ok = T;
    type Error = DecodeError;
    type Element<'s>
        = ScalarSink<u32>
    where
        Self: 's;
    fn element(&mut self) -> Result<ScalarSink<u32>, DecodeError> {
        match *self {
            Never::_Never(never, _) => match never {},
        }
    }
    fn end(self) -> Result<T, DecodeError> {
        match self {
            Never::_Never(never, _) => match never {},
        }
    }
}

impl<T> MapSink for Never<T> {
    type Ok = T;
    type Error = DecodeError;
    type Entry<'s>
        = ScalarSink<u32>
    where
        Self: 's;
    fn entry(&mut self, _: &str) -> Result<ScalarSink<u32>, DecodeError> {
        match *self {
            Never::_Never(never, _) => match never {},
        }
    }
    fn end(self) -> Result<T, DecodeError> {
        match self {
            Never::_Never(never, _) => match never {},
        }
    }
}

/// `Vec<T>`: accept a sequence, decode each element with `T`'s sink.
pub struct List<T>(PhantomData<T>);

impl<T: Decode> Sink for List<T> {
    type Ok = Vec<T>;
    type Error = DecodeError;
    type Seq = ListSeq<T>;
    type Map = Never<Vec<T>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Vec<T>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn seq(self, len: Option<usize>) -> Result<ListSeq<T>, DecodeError> {
        Ok(ListSeq(Vec::with_capacity(len.unwrap_or(0).min(1024))))
    }

    fn map(self, _: Option<usize>) -> Result<Never<Vec<T>>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }

    fn passthrough<P: Plaintext>(self, _: P) -> Result<Vec<T>, DecodeError> {
        Err(DecodeError::Expected("sequence"))
    }
}

pub struct ListSeq<T>(Vec<T>);

impl<T: Decode> SeqSink for ListSeq<T> {
    type Ok = Vec<T>;
    type Error = DecodeError;
    type Element<'s>
        = PushInto<'s, T>
    where
        Self: 's;

    fn element(&mut self) -> Result<PushInto<'_, T>, DecodeError> {
        Ok(PushInto(T::sink(), &mut self.0))
    }

    fn end(self) -> Result<Vec<T>, DecodeError> {
        Ok(self.0)
    }
}

/// `T`'s sink, pushing its result into the parent list. Pure forwarding.
pub struct PushInto<'s, T: Decode>(T::Sink, &'s mut Vec<T>);

impl<'s, T: Decode> Sink for PushInto<'s, T> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = PushSeq<'s, T, <T::Sink as Sink>::Seq>;
    type Map = PushSeq<'s, T, <T::Sink as Sink>::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), DecodeError> {
        self.1.push(self.0.scalar(ty, v)?);
        Ok(())
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(PushSeq(self.0.seq(len)?, self.1))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(PushSeq(self.0.map(len)?, self.1))
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<(), DecodeError> {
        self.1.push(self.0.passthrough(value)?);
        Ok(())
    }
}

pub struct PushSeq<'s, T, Q>(Q, &'s mut Vec<T>);

impl<'s, T, Q: SeqSink<Ok = T, Error = DecodeError>> SeqSink for PushSeq<'s, T, Q> {
    type Ok = ();
    type Error = DecodeError;
    type Element<'e>
        = Q::Element<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Self::Element<'_>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<(), DecodeError> {
        self.1.push(self.0.end()?);
        Ok(())
    }
}

impl<'s, T, Q: MapSink<Ok = T, Error = DecodeError>> MapSink for PushSeq<'s, T, Q> {
    type Ok = ();
    type Error = DecodeError;
    type Entry<'e>
        = Q::Entry<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<(), DecodeError> {
        self.1.push(self.0.end()?);
        Ok(())
    }
}

impl<T: Decode> Decode for Vec<T> {
    type Sink = List<T>;
    fn sink() -> List<T> {
        List(PhantomData)
    }
}
