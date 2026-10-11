//! Statically typed decryption as sinks: the replacement for `Decrypt`.
//!
//! A typed target is a sink that accepts one kind and refuses the rest.
//! Containers push into the parent. Only `u32`, `String` and `Vec<T>` are
//! here; a `#[derive(Decode)]` would generate the struct case.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use crate::decrypt::{decrypt_into, DecryptError};
use crate::encrypt::{Backend, Node};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use vitaminc_aead::IntoAad;

#[derive(Debug)]
pub enum DecodeError {
    /// The ciphertext holds a different kind than the target type.
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

/// Refuse every listed scalar method with `Expected($what)`.
macro_rules! refuse {
    ($what:expr; $($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, _: $ty) -> Result<Self::Ok, DecodeError> {
                Err(DecodeError::Expected($what))
            }
        )*
    };
}

/// Refuse containers and passthrough.
macro_rules! refuse_rest {
    ($what:expr) => {
        fn null(self) -> Result<Self::Ok, DecodeError> {
            Err(DecodeError::Expected($what))
        }
        fn undefined(self) -> Result<Self::Ok, DecodeError> {
            Err(DecodeError::Expected($what))
        }
        fn passthrough<P: Plaintext>(self, _: P) -> Result<Self::Ok, DecodeError> {
            Err(DecodeError::Expected($what))
        }
    };
}

/// Container sinks for a scalar target. Never built: `seq`/`map` refuse.
pub enum Never<T> {
    _Never(std::convert::Infallible, std::marker::PhantomData<T>),
}

impl<T> SeqSink for Never<T> {
    type Ok = T;
    type Error = DecodeError;
    type Element<'s>
        = U32
    where
        Self: 's;
    fn element(&mut self) -> Result<U32, DecodeError> {
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
        = U32
    where
        Self: 's;
    fn entry(&mut self, _: &str) -> Result<U32, DecodeError> {
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

pub struct U32;

impl Sink for U32 {
    type Ok = u32;
    type Error = DecodeError;
    type Seq = Never<u32>;
    type Map = Never<u32>;

    fn u32(self, v: u32) -> Result<u32, DecodeError> {
        Ok(v)
    }

    refuse! { "u32";
        bool(bool), i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u64(u64), u128(u128), f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal), str(&str), bytes(&[u8]),
    }
    refuse_rest!("u32");

    fn seq(self, _: Option<usize>) -> Result<Never<u32>, DecodeError> {
        Err(DecodeError::Expected("u32"))
    }
    fn map(self, _: Option<usize>) -> Result<Never<u32>, DecodeError> {
        Err(DecodeError::Expected("u32"))
    }
}

impl Decode for u32 {
    type Sink = U32;
    fn sink() -> U32 {
        U32
    }
}

pub struct Text;

impl Sink for Text {
    type Ok = String;
    type Error = DecodeError;
    type Seq = Never<String>;
    type Map = Never<String>;

    fn str(self, v: &str) -> Result<String, DecodeError> {
        Ok(v.to_owned())
    }

    refuse! { "string";
        bool(bool), i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u32(u32), u64(u64), u128(u128), f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal), bytes(&[u8]),
    }
    refuse_rest!("string");

    fn seq(self, _: Option<usize>) -> Result<Never<String>, DecodeError> {
        Err(DecodeError::Expected("string"))
    }
    fn map(self, _: Option<usize>) -> Result<Never<String>, DecodeError> {
        Err(DecodeError::Expected("string"))
    }
}

impl Decode for String {
    type Sink = Text;
    fn sink() -> Text {
        Text
    }
}

/// `Vec<T>`: accept a sequence, decode each element with `T`'s sink.
pub struct List<T>(std::marker::PhantomData<T>);

impl<T: Decode> Sink for List<T> {
    type Ok = Vec<T>;
    type Error = DecodeError;
    type Seq = ListSeq<T>;
    type Map = Never<Vec<T>>;

    fn seq(self, len: Option<usize>) -> Result<ListSeq<T>, DecodeError> {
        Ok(ListSeq(Vec::with_capacity(len.unwrap_or(0).min(1024))))
    }

    refuse! { "sequence";
        bool(bool), i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u32(u32), u64(u64), u128(u128), f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal), str(&str), bytes(&[u8]),
    }
    refuse_rest!("sequence");

    fn map(self, _: Option<usize>) -> Result<Never<Vec<T>>, DecodeError> {
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

macro_rules! forward {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<(), DecodeError> {
                self.1.push(self.0.$method(v)?);
                Ok(())
            }
        )*
    };
}

impl<'s, T: Decode> Sink for PushInto<'s, T> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = PushSeq<'s, T, <T::Sink as Sink>::Seq>;
    type Map = PushSeq<'s, T, <T::Sink as Sink>::Map>;

    fn null(self) -> Result<(), DecodeError> {
        self.1.push(self.0.null()?);
        Ok(())
    }

    fn undefined(self) -> Result<(), DecodeError> {
        self.1.push(self.0.undefined()?);
        Ok(())
    }

    forward! {
        bool(bool), i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u32(u32), u64(u64), u128(u128), f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal), str(&str), bytes(&[u8]),
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
        List(std::marker::PhantomData)
    }
}
