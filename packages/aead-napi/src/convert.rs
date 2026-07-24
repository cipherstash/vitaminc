//! Conversions between live JS values and [`NapiValue`].
//!
//! Both directions run on the JS thread (they need the `Env`); everything
//! between — encryption, decryption, transport — operates on the owned,
//! `Send` [`NapiValue`] tree.

use napi::bindgen_prelude::{
    Array, Buffer, FromNapiValue, JsValue, Object, ToNapiValue, Uint8Array, Unknown,
};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_protected::{Controlled, Protected};

use crate::value::NapiValue;

/// Maximum nesting depth accepted when converting a JS value tree (and when
/// rebuilding one). Bounds recursion so a hostile deeply-nested input cannot
/// overflow the stack.
pub(crate) const MAX_DEPTH: usize = 128;

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

fn js_to_value(unknown: Unknown<'_>, depth: usize) -> Result<NapiValue> {
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    match unknown.get_type()? {
        ValueType::Null => Ok(NapiValue::Null),
        ValueType::Undefined => Ok(NapiValue::Undefined),
        ValueType::Boolean => Ok(NapiValue::Bool(bool::from_unknown(unknown)?)),
        ValueType::Number => Ok(NapiValue::Number(f64::from_unknown(unknown)?)),
        ValueType::String => {
            // `String::from_unknown` copies out of the V8 heap; the copy is
            // moved into `Protected` without further duplication. The V8
            // original is owned by the engine and cannot be wiped from here.
            let s = String::from_unknown(unknown)?;
            Ok(NapiValue::String(Protected::new(s.into_bytes())))
        }
        ValueType::Object => {
            if unknown.is_buffer()? {
                let buf = Buffer::from_unknown(unknown)?;
                Ok(NapiValue::Bytes(Protected::new(buf.to_vec())))
            } else if unknown.is_typedarray()? {
                // Only byte views are meaningful plaintext; other typed
                // arrays (Float64Array, …) are rejected by the cast.
                let arr = Uint8Array::from_unknown(unknown)?;
                Ok(NapiValue::Bytes(Protected::new(arr.to_vec())))
            } else if unknown.is_array()? {
                let arr = Array::from_unknown(unknown)?;
                let len = arr.len();
                let mut items = Vec::with_capacity(len as usize);
                for i in 0..len {
                    let element: Unknown = arr.get(i)?.ok_or_else(|| {
                        Error::new(Status::InvalidArg, "sparse arrays are not supported")
                    })?;
                    items.push(js_to_value(element, depth + 1)?);
                }
                Ok(NapiValue::Array(items))
            } else if unknown.is_date()? {
                Err(Error::new(
                    Status::InvalidArg,
                    "Date values are not supported yet; pass a number or ISO string",
                ))
            } else {
                let obj = Object::from_unknown(unknown)?;
                let keys = Object::keys(&obj)?;
                let mut entries = Vec::with_capacity(keys.len());
                for key in keys {
                    if forbidden_key(&key) {
                        return Err(forbidden_key_error(&key));
                    }
                    let value: Unknown = obj.get(&key)?.ok_or_else(|| {
                        Error::new(Status::GenericFailure, "property vanished during read")
                    })?;
                    entries.push((key, js_to_value(value, depth + 1)?));
                }
                Ok(NapiValue::Object(entries))
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
        js_to_value(unknown, 0)
    }
}

fn value_to_js(env: sys::napi_env, value: NapiValue) -> Result<sys::napi_value> {
    match value {
        NapiValue::Null => unsafe {
            napi::bindgen_prelude::Null::to_napi_value(env, napi::bindgen_prelude::Null)
        },
        NapiValue::Undefined => unsafe { <()>::to_napi_value(env, ()) },
        NapiValue::Bool(b) => unsafe { bool::to_napi_value(env, b) },
        NapiValue::Number(n) => unsafe { f64::to_napi_value(env, n) },
        NapiValue::String(s) => {
            // Validated as UTF-8 on construction (both the decrypt visitor
            // and the JS-side conversion produce valid UTF-8).
            let utf8 = std::str::from_utf8(s.risky_ref())
                .map_err(|_| Error::new(Status::GenericFailure, "invalid UTF-8 string value"))?;
            unsafe { <&str>::to_napi_value(env, utf8) }
            // `s` drops (and wipes the Rust copy) here; the JS copy is owned
            // by the engine.
        }
        NapiValue::Bytes(b) => {
            let buf = Buffer::from(b.risky_ref().to_vec());
            unsafe { Buffer::to_napi_value(env, buf) }
        }
        NapiValue::Array(items) => {
            let raw_env = Env::from_raw(env);
            let mut arr = raw_env.create_array(items.len() as u32)?;
            for (i, item) in items.into_iter().enumerate() {
                let js = ValueHandle(item);
                arr.set(i as u32, js)?;
            }
            unsafe { Array::to_napi_value(env, arr) }
        }
        NapiValue::Object(entries) => {
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
struct ValueHandle(NapiValue);

impl ToNapiValue for ValueHandle {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        value_to_js(env, val.0)
    }
}

impl ToNapiValue for NapiValue {
    unsafe fn to_napi_value(env: sys::napi_env, val: Self) -> Result<sys::napi_value> {
        value_to_js(env, val)
    }
}

#[cfg(test)]
mod tests {
    use super::forbidden_key;

    #[test]
    fn forbidden_keys_are_rejected() {
        assert!(forbidden_key("__proto__"));
        assert!(forbidden_key("constructor"));
        assert!(forbidden_key("prototype"));
        assert!(!forbidden_key("proto"));
        assert!(!forbidden_key("name"));
        assert!(!forbidden_key(""));
    }
}
