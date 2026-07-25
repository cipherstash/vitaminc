//! Conversions between live JS values and [`FfiValue`].
//!
//! Both directions run on the JS thread (they need the `Env`); everything
//! between — encryption, decryption, transport — operates on the owned,
//! `Send` [`FfiValue`] tree from `vitaminc-aead-value`.
//!
//! # Numeric mapping
//!
//! JS `number` always converts to [`FfiValue::Float64`] — integral JS
//! numbers do **not** become an integer variant, preserving JS semantics
//! (`42` and `42.0` are the same value in JS). JS `BigInt` carries integer
//! typing: one that fits `i64` converts to [`FfiValue::Int64`]; one above
//! `i64::MAX` that still fits `u64` converts to [`FfiValue::UInt64`];
//! anything larger is rejected. JS has no 32-bit numeric types, so it
//! **never** encodes [`FfiValue::Int32`], [`FfiValue::UInt32`], or
//! [`FfiValue::Float32`].
//!
//! On the way out, values written by other languages (Python, Go) surface
//! losslessly: [`FfiValue::Float32`] widens exactly to a JS `number`
//! (`f64::from(f32)`); [`FfiValue::Float64`] is a `number`;
//! [`FfiValue::Int32`] / [`FfiValue::UInt32`] are always a `number` (their
//! magnitude never exceeds 2⁵³); [`FfiValue::Int64`] / [`FfiValue::UInt64`]
//! become a `number` when within `Number.MAX_SAFE_INTEGER` (2⁵³ − 1 in
//! magnitude) and a `BigInt` otherwise.

use napi::bindgen_prelude::{
    Array, BigInt, Buffer, FromNapiValue, JsObjectValue, JsValue, Object, ToNapiValue, Uint8Array,
    Unknown,
};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::{Controlled, Protected};

use crate::value::NapiValue;

/// Maximum nesting depth accepted when converting a JS value tree (and when
/// rebuilding one). Bounds recursion so a hostile deeply-nested input cannot
/// overflow the stack.
pub(crate) const MAX_DEPTH: usize = 128;

/// The largest integer JS numbers represent exactly: 2⁵³ − 1
/// (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Property names that must never be read from or written onto a plain JS
/// object: assigning them via `napi_set_property` triggers prototype-chain
/// semantics (prototype pollution), and accepting them on input would let a
/// value round-trip into that hazard.
pub(crate) fn forbidden_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

fn depth_error() -> Error {
    Error::new(Status::InvalidArg, "value is nested too deeply")
}

fn forbidden_key_error(key: &str) -> Error {
    Error::new(
        Status::InvalidArg,
        format!("property name is not allowed: {key}"),
    )
}

/// Initial `Vec` capacity granted to a JS-reported length before any element
/// has been validated. An array's reported length is attacker-cheap —
/// `new Array(2**32 - 1)` materialises no elements — so reserving the full
/// reported length up front would let a one-line input demand hundreds of
/// gigabytes and abort the whole Node process on allocation failure
/// (`handle_alloc_error` is not a catchable JS throw). Real elements grow
/// the `Vec` amortised past this cap.
const MAX_EAGER_CAPACITY: usize = 1024;

pub(crate) fn eager_capacity(reported_len: u32) -> usize {
    (reported_len as usize).min(MAX_EAGER_CAPACITY)
}

/// Own, enumerable, string-keyed property names of `obj`.
///
/// `Object::keys` (`napi_get_property_names`) walks the prototype chain —
/// per the Node-API spec it equals `napi_get_all_property_names` with
/// `include_prototypes | enumerable` — so a polluted `Object.prototype`
/// (or an instance with enumerable prototype members) would inject its
/// keys into the result, and inherited getters would run when the values
/// are read. Own-only enumeration forecloses both.
pub(crate) fn own_enumerable_keys(obj: &Object<'_>) -> Result<Vec<String>> {
    let raw = obj.value();
    let mut names = std::ptr::null_mut();
    let status = unsafe {
        sys::napi_get_all_property_names(
            raw.env,
            raw.value,
            sys::KeyCollectionMode::own_only,
            sys::KeyFilter::enumerable | sys::KeyFilter::skip_symbols,
            sys::KeyConversion::numbers_to_strings,
            &mut names,
        )
    };
    if status != sys::Status::napi_ok {
        return Err(Error::new(
            Status::GenericFailure,
            "failed to enumerate object properties",
        ));
    }
    let names = unsafe { Array::from_napi_value(raw.env, names) }?;
    let mut keys = Vec::with_capacity(eager_capacity(names.len()));
    for i in 0..names.len() {
        let key = names.get::<String>(i)?.ok_or_else(|| {
            Error::new(Status::GenericFailure, "property name vanished during read")
        })?;
        keys.push(key);
    }
    Ok(keys)
}

/// Fetch a property as the raw JS value, without [`Object::get`]'s
/// `undefined`-to-`None` mapping — `{ x: undefined }` has an own property
/// `x` (`Object.hasOwn` says so) and must round-trip, but `Object::get`
/// cannot distinguish its value from a missing property. A genuinely
/// missing property also comes back as `undefined`, which is exactly JS
/// property semantics.
pub(crate) fn get_property_unknown<'e>(obj: &Object<'e>, key: &str) -> Result<Unknown<'e>> {
    let raw = obj.value();
    let mut js_key = std::ptr::null_mut();
    let status = unsafe {
        sys::napi_create_string_utf8(
            raw.env,
            key.as_ptr().cast(),
            key.len() as isize,
            &mut js_key,
        )
    };
    if status != sys::Status::napi_ok {
        return Err(Error::new(
            Status::GenericFailure,
            "failed to create property key",
        ));
    }
    let mut value = std::ptr::null_mut();
    let status = unsafe { sys::napi_get_property(raw.env, raw.value, js_key, &mut value) };
    if status != sys::Status::napi_ok {
        return Err(Error::new(
            Status::GenericFailure,
            "failed to read object property",
        ));
    }
    unsafe { Unknown::from_napi_value(raw.env, value) }
}

/// Accept only plain objects — prototype `Object.prototype` (compared
/// against a fresh `{}` from the same realm) or `null`
/// (`Object.create(null)`).
///
/// Anything else stores its state in internal slots or carries class
/// behaviour that key/value enumeration silently loses: a `Map`'s or
/// `Set`'s contents enumerate as `{}`, a `RegExp` drops its pattern and
/// flags, an `ArrayBuffer` or `DataView` its bytes. Encrypting such a
/// value would destroy the payload with no error at either end, so refuse
/// loudly instead.
fn ensure_plain_object(obj: &Object<'_>) -> Result<()> {
    let proto = obj.get_prototype()?;
    if proto.get_type()? == ValueType::Null {
        return Ok(());
    }
    let env = Env::from_raw(obj.value().env);
    let baseline = Object::new(&env)?;
    let object_prototype = baseline.get_prototype()?;
    if env.strict_equals(proto, object_prototype)? {
        Ok(())
    } else {
        Err(Error::new(
            Status::InvalidArg,
            "only plain objects can be encrypted; Map, Set, class instances and other exotic \
             objects lose their contents under key enumeration — convert the value to a plain \
             object, array, string, number, Buffer, or Uint8Array first",
        ))
    }
}

fn js_to_value(unknown: Unknown<'_>, depth: usize) -> Result<FfiValue> {
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    match unknown.get_type()? {
        ValueType::Null => Ok(FfiValue::Null),
        ValueType::Undefined => Ok(FfiValue::Undefined),
        ValueType::Boolean => Ok(FfiValue::Bool(bool::from_unknown(unknown)?)),
        ValueType::Number => Ok(FfiValue::Float64(f64::from_unknown(unknown)?)),
        ValueType::BigInt => {
            let big = BigInt::from_unknown(unknown)?;
            // Signed first: a BigInt that fits `i64` is an `Int64`.
            let (signed, i64_lossless) = big.get_i64();
            if i64_lossless {
                return Ok(FfiValue::Int64(signed));
            }
            // Otherwise try unsigned: `get_u64` reports lossless only when the
            // value is non-negative and fits in a single 64-bit word, so a
            // positive BigInt in (i64::MAX, u64::MAX] lands here as `UInt64`.
            let (_sign, unsigned, u64_lossless) = big.get_u64();
            if u64_lossless {
                return Ok(FfiValue::UInt64(unsigned));
            }
            Err(Error::new(
                Status::InvalidArg,
                "BigInt value does not fit in a 64-bit integer",
            ))
        }
        ValueType::String => {
            // `String::from_unknown` copies out of the V8 heap; the copy is
            // moved into `Protected` without further duplication. The V8
            // original is owned by the engine and cannot be wiped from here.
            let s = String::from_unknown(unknown)?;
            Ok(FfiValue::String(Protected::new(s.into_bytes())))
        }
        ValueType::Object => {
            if unknown.is_buffer()? {
                let buf = Buffer::from_unknown(unknown)?;
                Ok(FfiValue::Bytes(Protected::new(buf.to_vec())))
            } else if unknown.is_typedarray()? {
                // Only byte views are meaningful plaintext; other typed
                // arrays (Float64Array, …) are rejected by the cast.
                let arr = Uint8Array::from_unknown(unknown)?;
                Ok(FfiValue::Bytes(Protected::new(arr.to_vec())))
            } else if unknown.is_array()? {
                let arr = Array::from_unknown(unknown)?;
                // The same JS value seen as an object, for per-index
                // own-property checks: `Array::get` wraps every in-bounds
                // hole in `Some(undefined)`, so on its own it can neither
                // reject sparseness nor resist a polluted `Array.prototype`
                // filling holes with inherited elements.
                let obj = Object::from_unknown(unknown)?;
                let len = arr.len();
                let mut items = Vec::with_capacity(eager_capacity(len));
                for i in 0..len {
                    // A hole has no own property; an explicit `undefined`
                    // element does. `[undefined]` round-trips; `[, , "x"]`
                    // and `new Array(n)` are rejected.
                    if !obj.has_own_property(&i.to_string())? {
                        return Err(Error::new(
                            Status::InvalidArg,
                            "sparse arrays are not supported",
                        ));
                    }
                    let element: Unknown = arr.get(i)?.ok_or_else(|| {
                        Error::new(Status::InvalidArg, "sparse arrays are not supported")
                    })?;
                    items.push(js_to_value(element, depth + 1)?);
                }
                Ok(FfiValue::Array(items))
            } else if unknown.is_date()? {
                Err(Error::new(
                    Status::InvalidArg,
                    "Date values are not supported yet; pass a number or ISO string",
                ))
            } else {
                let obj = Object::from_unknown(unknown)?;
                ensure_plain_object(&obj)?;
                let keys = own_enumerable_keys(&obj)?;
                let mut entries = Vec::with_capacity(keys.len());
                for key in keys {
                    if forbidden_key(&key) {
                        return Err(forbidden_key_error(&key));
                    }
                    // Raw fetch so an explicit `undefined` value survives as
                    // `FfiValue::Undefined` instead of erroring.
                    let value = get_property_unknown(&obj, &key)?;
                    entries.push((key, js_to_value(value, depth + 1)?));
                }
                Ok(FfiValue::Object(entries))
            }
        }
        other => Err(Error::new(
            Status::InvalidArg,
            format!("JS type cannot be encrypted: {other}"),
        )),
    }
}

impl FromNapiValue for NapiValue {
    unsafe fn from_napi_value(env: sys::napi_env, napi_val: sys::napi_value) -> Result<Self> {
        let unknown = unsafe { Unknown::from_napi_value(env, napi_val) }?;
        js_to_value(unknown, 0).map(NapiValue)
    }
}

fn value_to_js(env: sys::napi_env, value: FfiValue) -> Result<sys::napi_value> {
    match value {
        FfiValue::Null => unsafe {
            napi::bindgen_prelude::Null::to_napi_value(env, napi::bindgen_prelude::Null)
        },
        FfiValue::Undefined => unsafe { <()>::to_napi_value(env, ()) },
        FfiValue::Bool(b) => unsafe { bool::to_napi_value(env, b) },
        // Both float widths surface as a JS `number`; `f32` widens exactly.
        FfiValue::Float64(n) => unsafe { f64::to_napi_value(env, n) },
        FfiValue::Float32(f) => unsafe { f64::to_napi_value(env, f64::from(f)) },
        // 32-bit integers always fit `Number.MAX_SAFE_INTEGER`, so they are
        // always a plain JS `number`.
        FfiValue::Int32(i) => unsafe { f64::to_napi_value(env, i as f64) },
        FfiValue::UInt32(u) => unsafe { f64::to_napi_value(env, u as f64) },
        FfiValue::Int64(i) => {
            // Exactly representable → plain number (the common case, and
            // what JS callers expect for e.g. a Python-written `30`).
            // Beyond ±MAX_SAFE_INTEGER → BigInt, losslessly.
            if i.abs() <= MAX_SAFE_INTEGER {
                unsafe { f64::to_napi_value(env, i as f64) }
            } else {
                unsafe { BigInt::to_napi_value(env, BigInt::from(i)) }
            }
        }
        FfiValue::UInt64(u) => {
            // Same rule as `Int64`: exactly representable → plain number, else
            // BigInt. `MAX_SAFE_INTEGER` is non-negative so the cast is safe.
            if u <= MAX_SAFE_INTEGER as u64 {
                unsafe { f64::to_napi_value(env, u as f64) }
            } else {
                unsafe { BigInt::to_napi_value(env, BigInt::from(u)) }
            }
        }
        FfiValue::String(s) => {
            // Validated as UTF-8 on construction (both the decrypt visitor
            // and the JS-side conversion produce valid UTF-8).
            let utf8 = std::str::from_utf8(s.risky_ref())
                .map_err(|_| Error::new(Status::GenericFailure, "invalid UTF-8 string value"))?;
            unsafe { <&str>::to_napi_value(env, utf8) }
            // `s` drops (and wipes the Rust copy) here; the JS copy is owned
            // by the engine.
        }
        FfiValue::Bytes(b) => {
            let buf = Buffer::from(b.risky_ref().to_vec());
            unsafe { Buffer::to_napi_value(env, buf) }
        }
        FfiValue::Array(items) => {
            let raw_env = Env::from_raw(env);
            let mut arr = raw_env.create_array(items.len() as u32)?;
            for (i, item) in items.into_iter().enumerate() {
                let js = ValueHandle(item);
                arr.set(i as u32, js)?;
            }
            unsafe { Array::to_napi_value(env, arr) }
        }
        FfiValue::Object(entries) => {
            let raw_env = Env::from_raw(env);
            let mut obj = Object::new(&raw_env)?;
            for (key, value) in entries {
                // Keys decrypted from a ciphertext are attacker-influenced
                // in principle; never assign prototype-polluting names.
                if forbidden_key(&key) {
                    return Err(forbidden_key_error(&key));
                }
                obj.set(&key, ValueHandle(value))?;
            }
            unsafe { Object::to_napi_value(env, obj) }
        }
    }
}

/// Internal newtype so recursive positions (array elements, object values)
/// can go through `ToNapiValue` without exposing a blanket recursive impl
/// signature difference.
struct ValueHandle(FfiValue);

impl ToNapiValue for ValueHandle {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        value_to_js(env, val.0)
    }
}

impl ToNapiValue for NapiValue {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        value_to_js(env, val.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{eager_capacity, forbidden_key, MAX_EAGER_CAPACITY, MAX_SAFE_INTEGER};

    #[test]
    fn forbidden_keys_are_rejected() {
        assert!(forbidden_key("__proto__"));
        assert!(forbidden_key("constructor"));
        assert!(forbidden_key("prototype"));
        assert!(!forbidden_key("proto"));
        assert!(!forbidden_key("name"));
        assert!(!forbidden_key(""));
    }

    #[test]
    fn max_safe_integer_matches_js() {
        // Number.MAX_SAFE_INTEGER
        assert_eq!(MAX_SAFE_INTEGER, 9_007_199_254_740_991);
    }

    #[test]
    fn eager_capacity_passes_small_lengths_through() {
        assert_eq!(eager_capacity(0), 0);
        assert_eq!(eager_capacity(1), 1);
        assert_eq!(eager_capacity(37), 37);
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32),
            MAX_EAGER_CAPACITY
        );
    }

    #[test]
    fn eager_capacity_caps_attacker_reported_lengths() {
        assert_eq!(
            eager_capacity(MAX_EAGER_CAPACITY as u32 + 1),
            MAX_EAGER_CAPACITY
        );
        assert_eq!(eager_capacity(u32::MAX), MAX_EAGER_CAPACITY);
    }
}
