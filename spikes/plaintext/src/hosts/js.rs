//! Node side, compile-only (`cargo check --features napi`). Not run.
//!
//! A native binding is two pieces of Rust: a source that walks a live JS
//! value ([`JsRef`]) and a sink that builds JS values ([`JsBuilder`]). No
//! `Value` and no snapshot in between.
//!
//! The walk can stop with a JS error at any point (a getter throws, a string
//! has an unpaired surrogate) through `Error::source`. A live `Unknown` is
//! `!Send`, so to encrypt off the JS thread you'd snapshot first, with
//! `to_frame(JsRef(v))`, and encrypt the frame on the worker.
//!
//! The hardening in aead-napi's `convert.rs` (own-property re-checks,
//! prototype rules, depth) is left out.

use chrono::{DateTime, NaiveDate, Utc};
use napi::bindgen_prelude::{
    Array, BigInt, Buffer, FromNapiValue, JsObjectValue, JsValue, KeyCollectionMode, KeyConversion,
    KeyFilter, Null, Object, ToNapiValue, Uint8Array, Unknown, Utf16String,
};
use napi::{Env, Property, ValueType};
use rust_decimal::Decimal;
use vitaminc_aead::{Context, LocalCipherText};
use vitaminc_encrypt::Aes256Cipher;

use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
use crate::{decrypt_into, encrypt as encrypt_any, DecryptError, EncryptError, Node};

pub fn encrypt(value: Unknown<'_>, cipher: &Aes256Cipher, aad: &[u8]) -> napi::Result<Node<LocalCipherText>> {
    encrypt_any(JsRef(value), cipher, Context::from_encoded(aad)).map_err(|e| match e {
        // The JS error that stopped the walk, back to JS.
        EncryptError::Source(e) => napi::Error::from_reason(e.to_string()),
        _ => napi::Error::from_reason("encryption failed"),
    })
}

pub fn decrypt<'e>(env: &'e Env, ct: Node<LocalCipherText>, cipher: &Aes256Cipher, aad: &[u8]) -> napi::Result<Unknown<'e>> {
    decrypt_into(cipher, ct, Context::from_encoded(aad), JsBuilder::root(env)).map_err(|e| match e {
        DecryptError::Sink(JsError(e)) => e,
        _ => napi::Error::from_reason("decryption failed"),
    })
}

fn text(value: Unknown<'_>) -> napi::Result<String> {
    let utf16 = Utf16String::from_unknown(value)?;
    String::from_utf16(&utf16).map_err(|_| napi::Error::from_reason("unpaired surrogate"))
}

/// A live JS value as a source.
pub struct JsRef<'e>(pub Unknown<'e>);

fn fail<E: Error>(e: napi::Error) -> E {
    E::source(SourceError::msg(e.to_string()))
}

impl Plaintext for JsRef<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let v = self.0;
        match v.get_type().map_err(fail)? {
            ValueType::Null => sink.null(),
            ValueType::Undefined => sink.undefined(),
            ValueType::Boolean => sink.bool(bool::from_unknown(v).map_err(fail)?),
            ValueType::Number => sink.f64(f64::from_unknown(v).map_err(fail)?),
            ValueType::BigInt => {
                let big = BigInt::from_unknown(v).map_err(fail)?;
                bigint(big.sign_bit, &big.words, sink)
            }
            ValueType::String => sink.str(&text(v).map_err(fail)?),
            ValueType::Object if v.is_buffer().map_err(fail)? => sink.bytes(&Buffer::from_unknown(v).map_err(fail)?),
            ValueType::Object if v.is_typedarray().map_err(fail)? => {
                sink.bytes(&Uint8Array::from_unknown(v).map_err(fail)?)
            }
            ValueType::Object if v.is_array().map_err(fail)? => {
                let arr = Array::from_unknown(v).map_err(fail)?;
                let mut seq = sink.seq(Some(arr.len() as usize))?;
                for i in 0..arr.len() {
                    let item: Unknown = arr
                        .get(i)
                        .map_err(fail)?
                        .ok_or_else(|| S::Error::source(SourceError::msg("sparse array")))?;
                    JsRef(item).visit(seq.element()?)?;
                }
                seq.end()
            }
            ValueType::Object if v.is_date().map_err(fail)? => {
                let ms = napi::JsDate::from_unknown(v).map_err(fail)?.value_of().map_err(fail)?;
                let ts = (ms.is_finite() && ms.fract() == 0.0)
                    .then(|| DateTime::from_timestamp_millis(ms as i64))
                    .flatten()
                    .ok_or_else(|| S::Error::source(SourceError::msg("invalid Date")))?;
                sink.timestamp(ts)
            }
            ValueType::Object => {
                let obj = Object::from_unknown(v).map_err(fail)?;
                let names = obj
                    .get_all_property_names(KeyCollectionMode::OwnOnly, KeyFilter::Enumerable, KeyConversion::NumbersToStrings)
                    .map_err(fail)?;
                let mut keys = Vec::new();
                for i in 0..names.get_array_length().map_err(fail)? {
                    let handle = names.get_element::<Unknown>(i).map_err(fail)?;
                    if handle.get_type().map_err(fail)? != ValueType::Symbol {
                        keys.push((handle, text(handle).map_err(fail)?));
                    }
                }
                let mut map = sink.map(Some(keys.len()))?;
                for (handle, key) in keys {
                    // A getter runs here. If it throws, the walk stops.
                    let value = obj.get_property_unchecked(handle).map_err(fail)?;
                    JsRef(value).visit(map.entry(&key)?)?;
                }
                map.end()
            }
            other => Err(S::Error::source(SourceError::msg(format!("JS type cannot be encrypted: {other}")))),
        }
    }
}

/// Smallest width that fits, signed first, as aead-napi does today.
fn bigint<S: Sink>(negative: bool, words: &[u64], sink: S) -> Result<S::Ok, S::Error> {
    let range = || S::Error::source(SourceError::msg("BigInt out of range"));
    if words.get(2..).is_some_and(|tail| tail.iter().any(|&w| w != 0)) {
        return Err(range());
    }
    let m = u128::from(words.first().copied().unwrap_or(0)) | (u128::from(words.get(1).copied().unwrap_or(0)) << 64);
    if negative && m != 0 {
        if m > (1u128 << 127) {
            return Err(range());
        }
        let v = (m as i128).wrapping_neg();
        return match () {
            _ if i8::try_from(v).is_ok() => sink.i8(v as i8),
            _ if i16::try_from(v).is_ok() => sink.i16(v as i16),
            _ if i32::try_from(v).is_ok() => sink.i32(v as i32),
            _ if i64::try_from(v).is_ok() => sink.i64(v as i64),
            _ => sink.i128(v),
        };
    }
    match () {
        _ if i8::try_from(m).is_ok() => sink.i8(m as i8),
        _ if u8::try_from(m).is_ok() => sink.u8(m as u8),
        _ if i16::try_from(m).is_ok() => sink.i16(m as i16),
        _ if u16::try_from(m).is_ok() => sink.u16(m as u16),
        _ if i32::try_from(m).is_ok() => sink.i32(m as i32),
        _ if u32::try_from(m).is_ok() => sink.u32(m as u32),
        _ if i64::try_from(m).is_ok() => sink.i64(m as i64),
        _ if u64::try_from(m).is_ok() => sink.u64(m as u64),
        _ if i128::try_from(m).is_ok() => sink.i128(m as i128),
        _ => sink.u128(m),
    }
}

/// The sink side: build JS values directly. Replaces `value_to_js`.
#[derive(Debug)]
pub struct JsError(pub napi::Error);

impl Error for JsError {
    fn source(error: SourceError) -> Self {
        Self(napi::Error::from_reason(error.to_string()))
    }
}

impl From<napi::Error> for JsError {
    fn from(e: napi::Error) -> Self {
        Self(e)
    }
}

/// Where a built JS value goes: back to the caller, or onto a parent.
pub trait Target<'e> {
    type Ok;
    fn put(self, env: &'e Env, value: Unknown<'e>) -> Result<Self::Ok, JsError>;
}

pub struct Root;

impl<'e> Target<'e> for Root {
    type Ok = Unknown<'e>;
    fn put(self, _: &'e Env, value: Unknown<'e>) -> Result<Unknown<'e>, JsError> {
        Ok(value)
    }
}

/// One own property of a parent being built.
pub struct Slot<'s>(&'s mut Vec<Property>, String);

impl<'e> Target<'e> for Slot<'_> {
    type Ok = ();
    fn put(self, env: &'e Env, value: Unknown<'e>) -> Result<(), JsError> {
        self.0.push(Property::new().with_name(env, &self.1)?.with_value(&value));
        Ok(())
    }
}

pub struct JsBuilder<'e, T> {
    env: &'e Env,
    target: T,
}

impl<'e> JsBuilder<'e, Root> {
    pub fn root(env: &'e Env) -> Self {
        Self { env, target: Root }
    }
}

impl<'e, T: Target<'e>> JsBuilder<'e, T> {
    fn put(self, value: impl ToNapiValue) -> Result<T::Ok, JsError> {
        let value = value.into_unknown(self.env)?;
        self.target.put(self.env, value)
    }

    fn wrapper(self, key: &str, text: String) -> Result<T::Ok, JsError> {
        let mut obj = Object::new(self.env)?;
        let value = text.into_unknown(self.env)?;
        obj.define_properties(&[Property::new().with_name(self.env, key)?.with_value(&value)])?;
        self.put(obj)
    }
}

macro_rules! bigint_out {
    ($($method:ident($ty:ty) => $wide:ty),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<T::Ok, JsError> {
                self.put(BigInt::from(<$wide>::from(v)))
            }
        )*
    };
}

impl<'e, T: Target<'e>> Sink for JsBuilder<'e, T> {
    type Ok = T::Ok;
    type Error = JsError;
    type Seq = JsContainer<'e, T>;
    type Map = JsContainer<'e, T>;

    fn null(self) -> Result<T::Ok, JsError> {
        self.put(Null)
    }

    fn undefined(self) -> Result<T::Ok, JsError> {
        self.put(())
    }

    fn bool(self, v: bool) -> Result<T::Ok, JsError> {
        self.put(v)
    }

    // Every integer kind surfaces as a BigInt.
    bigint_out! {
        i8(i8) => i128, i16(i16) => i128, i32(i32) => i128, i64(i64) => i128, i128(i128) => i128,
        u8(u8) => u128, u16(u16) => u128, u32(u32) => u128, u64(u64) => u128, u128(u128) => u128,
    }

    fn f32(self, v: f32) -> Result<T::Ok, JsError> {
        self.put(f64::from(v))
    }

    fn f64(self, v: f64) -> Result<T::Ok, JsError> {
        self.put(v)
    }

    fn date(self, v: NaiveDate) -> Result<T::Ok, JsError> {
        self.wrapper("date", v.to_string())
    }

    fn timestamp(self, v: DateTime<Utc>) -> Result<T::Ok, JsError> {
        if v.timestamp_subsec_nanos().is_multiple_of(1_000_000) && v.timestamp_subsec_nanos() < 1_000_000_000 {
            let date = self.env.create_date(v.timestamp_millis() as f64)?;
            self.put(date)
        } else {
            self.wrapper("timestamp", v.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        }
    }

    fn decimal(self, v: Decimal) -> Result<T::Ok, JsError> {
        self.wrapper("decimal", v.to_string())
    }

    fn str(self, v: &str) -> Result<T::Ok, JsError> {
        self.put(v)
    }

    fn bytes(self, v: &[u8]) -> Result<T::Ok, JsError> {
        self.put(Buffer::from(v.to_vec()))
    }

    fn seq(self, _: Option<usize>) -> Result<JsContainer<'e, T>, JsError> {
        Ok(JsContainer::new(self, true))
    }

    fn map(self, _: Option<usize>) -> Result<JsContainer<'e, T>, JsError> {
        Ok(JsContainer::new(self, false))
    }

    /// The marking steers encryption only; decrypted, it's a plain value.
    fn passthrough<P: Plaintext>(self, value: P) -> Result<T::Ok, JsError> {
        value.visit(self)
    }
}

/// An array or object being built. Properties are collected and defined
/// as own properties at the end, so no setter on a prototype runs.
pub struct JsContainer<'e, T> {
    parent: JsBuilder<'e, T>,
    array: bool,
    props: Vec<Property>,
}

impl<'e, T: Target<'e>> JsContainer<'e, T> {
    fn new(parent: JsBuilder<'e, T>, array: bool) -> Self {
        Self { parent, array, props: Vec::new() }
    }

    fn child(&mut self, key: String) -> JsBuilder<'e, Slot<'_>> {
        JsBuilder {
            env: self.parent.env,
            target: Slot(&mut self.props, key),
        }
    }

    fn finish(self) -> Result<T::Ok, JsError> {
        let env = self.parent.env;
        let mut obj = if self.array {
            let len = u32::try_from(self.props.len()).map_err(|_| napi::Error::from_reason("array too long"))?;
            Object::from_unknown(env.create_array(len)?.to_unknown())?
        } else {
            Object::new(env)?
        };
        obj.define_properties(&self.props)?;
        self.parent.put(obj)
    }
}

impl<'e, T: Target<'e>> SeqSink for JsContainer<'e, T> {
    type Ok = T::Ok;
    type Error = JsError;
    type Element<'s>
        = JsBuilder<'e, Slot<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, JsError> {
        let index = self.props.len().to_string();
        Ok(self.child(index))
    }

    fn end(self) -> Result<T::Ok, JsError> {
        self.finish()
    }
}

impl<'e, T: Target<'e>> MapSink for JsContainer<'e, T> {
    type Ok = T::Ok;
    type Error = JsError;
    type Entry<'s>
        = JsBuilder<'e, Slot<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, JsError> {
        if matches!(key, "__proto__" | "constructor" | "prototype") {
            return Err(JsError(napi::Error::from_reason(format!("property name is not allowed: {key}"))));
        }
        Ok(self.child(key.to_owned()))
    }

    fn end(self) -> Result<T::Ok, JsError> {
        self.finish()
    }
}
