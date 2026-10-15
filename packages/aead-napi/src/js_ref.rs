//! [`JsRef`]: a live JavaScript value as a [`Plaintext`] source.
//!
//! The walk runs on the JavaScript thread, reading each value as it goes:
//! no tree is built, and a scalar leaves the engine only to go straight to
//! the sink. ADR 0001 section 6 gives the mapping:
//!
//! | JavaScript             | `Sink` call                                     |
//! | ---------------------- | ----------------------------------------------- |
//! | `null`                 | `scalar(None, Null)`                            |
//! | `undefined`            | `scalar(Some(Undefined), Null)`                 |
//! | `boolean`              | `scalar(None, Bool)`                            |
//! | `number`               | `scalar(None, Float(F64))`                      |
//! | `bigint`               | `scalar(None, Int(narrowest fitting width))`    |
//! | `string`               | `scalar(None, Text)`                            |
//! | `Buffer`, `Uint8Array` | `scalar(None, Bytes)`                           |
//! | `Date`                 | `scalar(Some(Timestamp(Millis)), Int(I64(ms)))` |
//! | `Array`                | `seq`, then `element()` per index               |
//! | plain object           | `map`, then `entry(key)` per own property       |
//!
//! The wrapper classes carry the scalars JavaScript has no type for:
//! `VcDate` is `Date` over the day count, `VcTimestamp` is
//! `Timestamp(Nanos)` over the nanosecond count, `VcDecimal` is `Decimal`
//! over the mantissa and `VcUuid` is `Uuid` over sixteen bytes.
//!
//! A getter that throws, a string with an unpaired surrogate, a BigInt out
//! of range or a `Date` outside chrono's range stops the walk through
//! [`Error::source`](vitaminc_aead::plaintext::Error::source), and comes
//! back to JavaScript as that error: see [`JsFault`].

use napi::bindgen_prelude::{
    Array, BigInt, Buffer, FromNapiValue, JsObjectValue, JsValue, Object, Uint8Array, Unknown,
};
use napi::{Env, Error, Status, ValueType};
use vitaminc_aead::frame::FrameWriteError;
use vitaminc_aead::plaintext::{Error as _, SourceError};
use vitaminc_aead::{
    to_frame, Float, Logical, MapSink, Physical, Plaintext, SeqSink, Sink, TimeUnit,
};
use vitaminc_protected::Protected;

use crate::error::JsFault;
use crate::js::{
    depth_error, forbidden_key, forbidden_key_error, get_own, is_plain_object, lossless_string,
    not_plain_error, own_enumerable_keys, MAX_DEPTH,
};
use crate::scalar::{self, ConversionError};
use crate::wrappers::{Wrapper, Wrappers};

/// A live JavaScript value, walked in place on the JavaScript thread.
pub struct JsRef<'e> {
    value: Unknown<'e>,
    depth: usize,
}

impl<'e> JsRef<'e> {
    pub fn new(value: Unknown<'e>) -> Self {
        Self { value, depth: 0 }
    }

    /// A value that sits `depth` levels down in a larger structure, so
    /// the nesting limit counts the whole structure.
    pub(crate) fn at_depth(value: Unknown<'e>, depth: usize) -> Self {
        Self { value, depth }
    }

    /// Snapshot the value as a frame, on the JavaScript thread, so it can be
    /// encrypted on a worker with no JavaScript access. The frame is
    /// plaintext and comes back wiped on drop.
    pub fn to_frame(self) -> napi::Result<Protected<Vec<u8>>> {
        to_frame(self).map_err(frame_error)
    }
}

impl Plaintext for JsRef<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        walk(self.value, self.depth, sink)
    }
}

/// A frame writer's refusal as the napi error to hand back.
pub(crate) fn frame_error(error: FrameWriteError) -> Error {
    match error {
        FrameWriteError::Source(source) => JsFault::from_source(&source),
        FrameWriteError::TooDeep => depth_error(),
        other => Error::new(Status::InvalidArg, other.to_string()),
    }
}

/// A JavaScript-side failure, as the sink's error.
fn fault<S: Sink>(error: Error) -> S::Error {
    S::Error::source(SourceError::new(JsFault::from(error)))
}

/// A scalar conversion failure: thrown into JavaScript as a `TypeError`
/// with the error's stable code, and carried as the pending exception.
fn conversion<S: Sink>(env: &Env, error: ConversionError) -> S::Error {
    let error = match env.throw_type_error(&error.to_string(), Some(error.code())) {
        Ok(()) => Error::new(Status::PendingException, error.to_string()),
        Err(error) => error,
    };
    fault::<S>(error)
}

fn walk<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    if depth > MAX_DEPTH {
        return Err(fault::<S>(depth_error()));
    }
    match value.get_type().map_err(fault::<S>)? {
        ValueType::Null => sink.scalar(None, Physical::Null),
        ValueType::Undefined => sink.scalar(Some(Logical::Undefined), Physical::Null),
        ValueType::Boolean => {
            let b = bool::from_unknown(value).map_err(fault::<S>)?;
            sink.scalar(None, Physical::Bool(b))
        }
        ValueType::Number => {
            let n = f64::from_unknown(value).map_err(fault::<S>)?;
            sink.scalar(None, Physical::Float(Float::F64(n)))
        }
        ValueType::BigInt => {
            let env = Env::from_raw(value.value().env);
            let big = BigInt::from_unknown(value).map_err(fault::<S>)?;
            let int =
                scalar::bigint(big.sign_bit, &big.words).map_err(|e| conversion::<S>(&env, e))?;
            sink.scalar(None, Physical::Int(int))
        }
        ValueType::String => {
            // The text is copied out of the engine to check it and goes
            // straight to the sink; the V8 original cannot be wiped from here.
            let text = lossless_string(value, "string").map_err(fault::<S>)?;
            sink.scalar(None, Physical::Text(&text))
        }
        ValueType::Object => object(value, depth, sink),
        other => Err(fault::<S>(Error::new(
            Status::InvalidArg,
            format!("JS type cannot be encrypted: {other}"),
        ))),
    }
}

/// Dispatch an object. The scalar shapes are read in helpers whose frames
/// are gone before the containers recurse, so the stack a nested level
/// costs is the recursion's own and a document at the depth limit walks
/// in a debug build too.
fn object<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    if value.is_buffer().map_err(fault::<S>)? {
        return buffer(value, sink);
    }
    if value.is_typedarray().map_err(fault::<S>)? {
        return typed_array(value, sink);
    }
    if value.is_array().map_err(fault::<S>)? {
        return array(value, depth, sink);
    }
    if value.is_date().map_err(fault::<S>)? {
        return date(value, sink);
    }
    match classify(value).map_err(fault::<S>)? {
        Some(wrapper) => wrapped(value, wrapper, sink),
        None => map(value, depth, sink),
    }
}

fn buffer<S: Sink>(value: Unknown<'_>, sink: S) -> Result<S::Ok, S::Error> {
    let buf = Buffer::from_unknown(value).map_err(fault::<S>)?;
    sink.scalar(None, Physical::Bytes(&buf))
}

/// Only byte views are meaningful plaintext; other typed arrays
/// (Float64Array, …) are rejected by the cast.
fn typed_array<S: Sink>(value: Unknown<'_>, sink: S) -> Result<S::Ok, S::Error> {
    let arr = Uint8Array::from_unknown(value).map_err(fault::<S>)?;
    sink.scalar(None, Physical::Bytes(&arr))
}

fn date<S: Sink>(value: Unknown<'_>, sink: S) -> Result<S::Ok, S::Error> {
    let env = Env::from_raw(value.value().env);
    let date = napi::JsDate::from_unknown(value).map_err(fault::<S>)?;
    let ms = date.value_of().map_err(fault::<S>)?;
    let count = scalar::date_millis(ms).map_err(|e| conversion::<S>(&env, e))?;
    sink.scalar(
        Some(Logical::Timestamp(TimeUnit::Millis)),
        Physical::Int(count),
    )
}

/// Which wrapper class an object is an instance of, or none for a plain
/// object. Anything else is refused.
fn classify(value: Unknown<'_>) -> napi::Result<Option<Wrapper>> {
    let env = Env::from_raw(value.value().env);
    let obj = Object::from_unknown(value)?;
    if let Some(wrapper) = Wrappers::get(&env)?.classify(&env, &value)? {
        return Ok(Some(wrapper));
    }
    if is_plain_object(&obj)? {
        Ok(None)
    } else {
        Err(not_plain_error())
    }
}

fn map<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    let obj = Object::from_unknown(value).map_err(fault::<S>)?;
    let keys = own_enumerable_keys(&obj).map_err(fault::<S>)?;
    let mut map = sink.map(Some(keys.len()))?;
    for key in keys {
        if forbidden_key(&key.name) {
            return Err(fault::<S>(forbidden_key_error(&key.name)));
        }
        // Raw fetch so an explicit `undefined` value survives as
        // `Undefined` instead of reading as a missing property.
        let value = get_own(&obj, &key).map_err(fault::<S>)?;
        walk(value, depth + 1, map.entry(&key.name)?)?;
    }
    map.end()
}

fn array<S: Sink>(value: Unknown<'_>, depth: usize, sink: S) -> Result<S::Ok, S::Error> {
    let arr = Array::from_unknown(value).map_err(fault::<S>)?;
    // The same JS value seen as an object, for per-index own-property
    // checks: `Array::get` wraps every in-bounds hole in `Some(undefined)`,
    // so on its own it can neither reject sparseness nor resist a polluted
    // `Array.prototype` filling holes with inherited elements.
    let obj = Object::from_unknown(value).map_err(fault::<S>)?;
    let len = arr.len();
    let mut seq = sink.seq(Some(len as usize))?;
    for i in 0..len {
        // A hole has no own property; an explicit `undefined` element does.
        // `[undefined]` round-trips; `[, , "x"]` and `new Array(n)` are
        // rejected.
        let sparse = || Error::new(Status::InvalidArg, "sparse arrays are not supported");
        if !obj.has_own_property(&i.to_string()).map_err(fault::<S>)? {
            return Err(fault::<S>(sparse()));
        }
        let element: Unknown = arr
            .get(i)
            .map_err(fault::<S>)?
            .ok_or_else(|| fault::<S>(sparse()))?;
        walk(element, depth + 1, seq.element()?)?;
    }
    seq.end()
}

/// A wrapper instance as its scalar. The text is read as an own string
/// property and checked here, so an instance made without the constructor
/// is held to the same rule.
fn wrapped<S: Sink>(value: Unknown<'_>, wrapper: Wrapper, sink: S) -> Result<S::Ok, S::Error> {
    let env = &Env::from_raw(value.value().env);
    let wrappers = Wrappers::get(env).map_err(fault::<S>)?;
    let instance = &Object::from_unknown(value).map_err(fault::<S>)?;
    let invalid = match wrapper {
        Wrapper::Date => ConversionError::InvalidDate,
        Wrapper::Timestamp => ConversionError::InvalidTimestamp,
        Wrapper::Decimal => ConversionError::InvalidDecimal,
        Wrapper::Uuid => ConversionError::InvalidUuid,
    };
    let text = match wrappers.text(instance).map_err(fault::<S>)? {
        Some(text) => lossless_string(text, wrapper.class_name()).map_err(fault::<S>)?,
        None => return Err(conversion::<S>(env, invalid)),
    };
    let convert = |e| conversion::<S>(env, e);
    match wrapper {
        Wrapper::Date => {
            let days = scalar::date(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Date), Physical::Int(days))
        }
        Wrapper::Timestamp => {
            let nanos = scalar::timestamp(&text).map_err(convert)?;
            sink.scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(nanos),
            )
        }
        Wrapper::Decimal => {
            let (scale, mantissa) = scalar::decimal(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Decimal { scale }), Physical::Int(mantissa))
        }
        Wrapper::Uuid => {
            let bytes = scalar::uuid(&text).map_err(convert)?;
            sink.scalar(Some(Logical::Uuid), Physical::Bytes(&bytes))
        }
    }
}
