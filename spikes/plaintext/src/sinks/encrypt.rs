//! Encryption as a sink: the self-describing (tagged) leaf format.
//!
//! [`Tagged`] turns any [`Plaintext`] into an `Encrypt`. Each scalar is
//! written as the same `Tagged*` leaf that `impl Encrypt for Value` uses, and
//! containers go through the same `encrypt_seq` and `encrypt_map` calls. So
//! the ciphertext is the same one `Value` produces, without building a
//! `Value` first. The tests check that call for call.
//!
//! `u32(34)` from Go now goes: frame bytes, `Frame::visit`, `Sink::u32`,
//! `TaggedUInt32::from(34)`, `encrypt_bytes_array`. No enum in between.

use std::any::Any;
use std::borrow::Cow;
use std::marker::PhantomData;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::{Cipher, Encrypt, IntoAad, MapCipher, SeqCipher};
use vitaminc_aead_value::tagged::*;
use vitaminc_protected::Protected;

use crate::model::{MapSink, Plaintext, SeqSink, Sink};
use crate::sinks::value_builder::to_value;

/// Encrypt `P` with self-describing leaves.
pub struct Tagged<P>(pub P);

impl<P: Plaintext> Encrypt for Tagged<P> {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0.visit(EncryptSink {
            cipher,
            aad,
            _lifetime: PhantomData,
        })
    }
}

pub struct EncryptSink<'a, C, A> {
    cipher: C,
    aad: A,
    _lifetime: PhantomData<&'a ()>,
}

macro_rules! leaf {
    ($($method:ident($ty:ty) => $leaf:ty),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<C::Ok, C::Error> {
                <$leaf>::from(v).encrypt_with_aad(self.cipher, self.aad)
            }
        )*
    };
}

impl<'a, C: Cipher, A: IntoAad<'a>> Sink for EncryptSink<'a, C, A> {
    type Ok = C::Ok;
    type Error = C::Error;
    type Seq = EncryptSeq<C::SeqCipher>;
    type Map = EncryptMap<C::MapCipher>;

    fn null(self) -> Result<C::Ok, C::Error> {
        TaggedNull::tag_only().encrypt_with_aad(self.cipher, self.aad)
    }

    fn undefined(self) -> Result<C::Ok, C::Error> {
        TaggedUndefined::tag_only().encrypt_with_aad(self.cipher, self.aad)
    }

    fn bool(self, v: bool) -> Result<C::Ok, C::Error> {
        if v {
            TaggedBoolTrue::tag_only().encrypt_with_aad(self.cipher, self.aad)
        } else {
            TaggedBoolFalse::tag_only().encrypt_with_aad(self.cipher, self.aad)
        }
    }

    leaf! {
        i8(i8) => TaggedInt8, i16(i16) => TaggedInt16, i32(i32) => TaggedInt32,
        i64(i64) => TaggedInt64, i128(i128) => TaggedInt128,
        u8(u8) => TaggedUInt8, u16(u16) => TaggedUInt16, u32(u32) => TaggedUInt32,
        u64(u64) => TaggedUInt64, u128(u128) => TaggedUInt128,
        f32(f32) => TaggedFloat32, f64(f64) => TaggedFloat64,
        date(NaiveDate) => TaggedDate, timestamp(DateTime<Utc>) => TaggedTimestamp,
        decimal(Decimal) => TaggedDecimal,
    }

    fn str(self, v: &str) -> Result<C::Ok, C::Error> {
        TaggedString::new(Protected::new(v.as_bytes().to_vec())).encrypt_with_aad(self.cipher, self.aad)
    }

    fn bytes(self, v: &[u8]) -> Result<C::Ok, C::Error> {
        TaggedBytes::new(Protected::new(v.to_vec())).encrypt_with_aad(self.cipher, self.aad)
    }

    fn seq(self, len: usize) -> Result<Self::Seq, C::Error> {
        Ok(EncryptSeq(self.cipher.encrypt_seq(Some(len), self.aad)))
    }

    fn map(self, _len: usize) -> Result<Self::Map, C::Error> {
        Ok(EncryptMap(self.cipher.encrypt_map(self.aad)))
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<C::Ok, C::Error> {
        // SPIKE: the passthrough channel is `Box<dyn Any>`, and the decrypt
        // side downcasts it to `Value`. So a passthrough subtree still has to
        // be built as a `Value`. It is non-sensitive by design, so this is a
        // shape constraint, not a custody one.
        let boxed: Box<dyn Any + Send + 'static> = Box::new(to_value(value));
        self.cipher.passthrough_boxed(boxed)
    }
}

pub struct EncryptSeq<S>(S);

impl<S: SeqCipher> SeqSink for EncryptSeq<S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn element<P: Plaintext>(self, value: P) -> Result<Self, S::Error> {
        // The cipher walks the element itself; see `SeqSink`.
        self.0.encrypt_next(Tagged(value)).map(EncryptSeq)
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        self.0.end()
    }
}

pub struct EncryptMap<M>(M);

impl<M: MapCipher> MapSink for EncryptMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn entry<P: Plaintext>(self, key: &str, value: P) -> Result<Self, M::Error> {
        self.0
            .encrypt_entry(Cow::Owned(key.to_owned()), Tagged(value))
            .map(EncryptMap)
    }

    fn end(self) -> Result<M::Ok, M::Error> {
        self.0.end()
    }
}
