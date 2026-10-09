//! Conversions between live JS values and [`Value`].
//!
//! Both directions run on the JS thread (they need the `Env`); everything
//! between — encryption, decryption, transport — operates on the owned,
//! `Send` [`Value`] tree from `vitaminc-aead-value`.
//!
//! # Numeric mapping
//!
//! JS `number` converts to `Float64`. BigInt uses the smallest fitting
//! integer width, preferring signed at a given width, through 128 bits.
//! Every integer kind decodes as BigInt. Date maps to Timestamp; calendar
//! dates use `{ date: "YYYY-MM-DD" }` and decimals `{ decimal: "1.50" }`.
//! Timestamps finer than Date's millisecond precision, and leap seconds,
//! use a `{ timestamp }` wrapper: RFC 3339, or an ISO 8601 expanded year
//! outside 0000-9999.
//!
//! The wrapper keys are reserved: a one-key object named `date`,
//! `timestamp` or `decimal` is always read as a wrapper, including one
//! decrypted from data another language wrote as an ordinary object.

use napi::bindgen_prelude::{
    Array, BigInt, Buffer, FromNapiValue, JsObjectValue, JsValue, Object, ToNapiValue, Uint8Array,
    Unknown, Utf16String,
};
use napi::{sys, Env, Error, Result, Status, ValueType};
use vitaminc_aead_value::Value;
use vitaminc_protected::{Controlled, Protected};

use crate::scalar;
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

// NOTE: there is intentionally no path here that constructs
// [`Value::Passthrough`]. Marking a field non-sensitive so it travels in
// the clear needs a deliberate JS-side opt-in (a wrapper the caller applies),
// which is not yet designed — building it would be silent, dangerous default
// behaviour otherwise. Until then JS input is always fully sealed; the decode
// direction still projects a passthrough produced elsewhere (e.g. a value
// written by another binding) onto its plain JS value. Follow-up: add an
// explicit passthrough marker type to the JS API.
/// Write `value` onto `obj` as an **own data property** (`defineProperty`
/// semantics: writable, enumerable, configurable) rather than through
/// [`Object::set`] (`napi_set_property`, `[[Set]]` semantics), which walks
/// the prototype chain: a polluted inherited setter on the key would receive
/// the decrypted plaintext (leak) and leave the result without the own
/// property (drop). The intake side already treats prototype pollution as
/// in-threat-model (`own_enumerable_keys`, `ensure_plain_object`); this
/// closes the output side.
pub(crate) fn define_own_property(
    obj: &Object<'_>,
    key: &str,
    value: sys::napi_value,
) -> Result<()> {
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
    let descriptor = sys::napi_property_descriptor {
        utf8name: std::ptr::null(),
        name: js_key,
        method: None,
        getter: None,
        setter: None,
        value,
        attributes: sys::PropertyAttributes::writable
            | sys::PropertyAttributes::enumerable
            | sys::PropertyAttributes::configurable,
        data: std::ptr::null_mut(),
    };
    let status = unsafe { sys::napi_define_properties(raw.env, raw.value, 1, &descriptor) };
    if status != sys::Status::napi_ok {
        return Err(Error::new(
            Status::GenericFailure,
            "failed to define object property",
        ));
    }
    Ok(())
}

fn js_to_value(unknown: Unknown<'_>, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(depth_error());
    }
    match unknown.get_type()? {
        ValueType::Null => Ok(Value::Null),
        ValueType::Undefined => Ok(Value::Undefined),
        ValueType::Boolean => Ok(Value::Bool(bool::from_unknown(unknown)?)),
        ValueType::Number => Ok(Value::Float64(f64::from_unknown(unknown)?)),
        ValueType::BigInt => {
            let env = Env::from_raw(unknown.value().env);
            let big = BigInt::from_unknown(unknown)?;
            scalar::bigint(big.sign_bit, &big.words).map_err(|e| conversion_error(env, e))
        }
        ValueType::String => {
            // Fetch as UTF-16 (JS's native representation) and convert with
            // `String::from_utf16`, which errors on unpaired surrogates. The
            // UTF-8 fetch (`napi_get_value_string_utf8`) would silently
            // replace them with U+FFFD — sealing a *mutated* plaintext that
            // no longer equals what the caller passed — so refuse loudly
            // instead. The converted copy moves into `Protected`; the V8
            // original is owned by the engine and cannot be wiped from here.
            let utf16 = Utf16String::from_unknown(unknown)?;
            let s = String::from_utf16(&utf16).map_err(|_| {
                Error::new(
                    Status::InvalidArg,
                    "string contains an unpaired surrogate and cannot be encrypted losslessly",
                )
            })?;
            Ok(Value::String(s.into()))
        }
        ValueType::Object => {
            if unknown.is_buffer()? {
                let buf = Buffer::from_unknown(unknown)?;
                Ok(Value::Bytes(Protected::new(buf.to_vec())))
            } else if unknown.is_typedarray()? {
                // Only byte views are meaningful plaintext; other typed
                // arrays (Float64Array, …) are rejected by the cast.
                let arr = Uint8Array::from_unknown(unknown)?;
                Ok(Value::Bytes(Protected::new(arr.to_vec())))
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
                Ok(Value::Array(items))
            } else if unknown.is_date()? {
                let env = Env::from_raw(unknown.value().env);
                let date = napi::JsDate::from_unknown(unknown)?;
                scalar::date_millis(date.value_of()?).map_err(|e| conversion_error(env, e))
            } else {
                let obj = Object::from_unknown(unknown)?;
                ensure_plain_object(&obj)?;
                let keys = own_enumerable_keys(&obj)?;
                if let [key] = keys.as_slice() {
                    use scalar::ConversionError::{InvalidDate, InvalidDecimal, InvalidTimestamp};
                    let parsed = match key.as_str() {
                        "date" => Some(
                            wrapper_text(&obj, key, InvalidDate)?
                                .and_then(|text| scalar::date(&text)),
                        ),
                        "timestamp" => Some(
                            wrapper_text(&obj, key, InvalidTimestamp)?
                                .and_then(|text| scalar::timestamp(&text)),
                        ),
                        "decimal" => Some(
                            wrapper_text(&obj, key, InvalidDecimal)?
                                .and_then(|text| scalar::decimal(&text)),
                        ),
                        _ => None,
                    };
                    if let Some(parsed) = parsed {
                        return parsed
                            .map_err(|e| conversion_error(Env::from_raw(obj.value().env), e));
                    }
                }
                let mut entries = Vec::with_capacity(keys.len());
                for key in keys {
                    if forbidden_key(&key) {
                        return Err(forbidden_key_error(&key));
                    }
                    // Raw fetch so an explicit `undefined` value survives as
                    // `Value::Undefined` instead of erroring.
                    let value = get_property_unknown(&obj, &key)?;
                    entries.push((key, js_to_value(value, depth + 1)?));
                }
                Ok(Value::Object(entries))
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

fn value_to_js(env: sys::napi_env, value: Value) -> Result<sys::napi_value> {
    match value {
        Value::Null => unsafe {
            napi::bindgen_prelude::Null::to_napi_value(env, napi::bindgen_prelude::Null)
        },
        Value::Undefined => unsafe { <()>::to_napi_value(env, ()) },
        Value::Bool(b) => unsafe { bool::to_napi_value(env, b) },
        // Both float widths surface as a JS `number`; `f32` widens exactly.
        Value::Float64(n) => unsafe { f64::to_napi_value(env, n) },
        Value::Float32(f) => unsafe { f64::to_napi_value(env, f64::from(f)) },
        Value::Int8(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(i128::from(v))) },
        Value::UInt8(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(u128::from(v))) },
        Value::Int16(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(i128::from(v))) },
        Value::UInt16(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(u128::from(v))) },
        Value::Int32(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(i128::from(v))) },
        Value::UInt32(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(u128::from(v))) },
        Value::Int64(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(v)) },
        Value::UInt64(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(v)) },
        Value::Int128(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(v)) },
        Value::UInt128(v) => unsafe { BigInt::to_napi_value(env, BigInt::from(v)) },
        Value::Date(v) => wrapper_to_js(env, "date", v.to_string()),
        Value::Decimal(v) => wrapper_to_js(env, "decimal", v.to_string()),
        Value::Timestamp(v) => {
            // chrono's range (about ±8.21e15 ms) lies inside JS Date's
            // (±8.64e15 ms), so only precision and leap seconds need a wrapper.
            if v.timestamp_subsec_nanos() < 1_000_000_000
                && v.timestamp_subsec_nanos() % 1_000_000 == 0
            {
                Ok(Env::from_raw(env)
                    .create_date(v.timestamp_millis() as f64)?
                    .value()
                    .value)
            } else {
                wrapper_to_js(
                    env,
                    "timestamp",
                    v.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                )
            }
        }
        Value::String(s) => {
            // Validated as UTF-8 on construction (both the decrypt visitor
            // and the JS-side conversion produce valid UTF-8).
            let utf8 = std::str::from_utf8(s.risky_ref())
                .map_err(|_| Error::new(Status::GenericFailure, "invalid UTF-8 string value"))?;
            unsafe { <&str>::to_napi_value(env, utf8) }
            // `s` drops (and wipes the Rust copy) here; the JS copy is owned
            // by the engine.
        }
        Value::Bytes(b) => {
            let buf = Buffer::from(b.risky_ref().to_vec());
            unsafe { Buffer::to_napi_value(env, buf) }
        }
        Value::Array(items) => {
            let raw_env = Env::from_raw(env);
            let mut arr = raw_env.create_array(items.len() as u32)?;
            for (i, item) in items.into_iter().enumerate() {
                let js = ValueHandle(item);
                arr.set(i as u32, js)?;
            }
            unsafe { Array::to_napi_value(env, arr) }
        }
        Value::Object(entries) => {
            let raw_env = Env::from_raw(env);
            let obj = Object::new(&raw_env)?;
            for (key, value) in entries {
                // Keys decrypted from a ciphertext are attacker-influenced
                // in principle; never assign prototype-polluting names.
                if forbidden_key(&key) {
                    return Err(forbidden_key_error(&key));
                }
                let js_value = value_to_js(env, value)?;
                define_own_property(&obj, &key, js_value)?;
            }
            unsafe { Object::to_napi_value(env, obj) }
        }
        // A passthrough subtree projects onto its plain JS value: the marking
        // exists to steer encryption, and once decrypted the field is an
        // ordinary value to the application. (Round-tripping the *marking*
        // back into a re-encryptable JS value is future work — see
        // `js_to_value`, which has no passthrough constructor yet.)
        Value::Passthrough(inner) => value_to_js(env, *inner),
        _ => Err(Error::new(Status::GenericFailure, "unsupported value kind")),
    }
}

/// The string payload of a one-key scalar wrapper. Any other payload
/// (`{ date: new Date() }`, `{ decimal: 1n }`, ...) is refused with the
/// wrapper's own typed error rather than a generic N-API one; a non-finite
/// number in `{ decimal }` keeps its distinct code.
fn wrapper_text(
    obj: &Object,
    key: &str,
    invalid: scalar::ConversionError,
) -> Result<std::result::Result<String, scalar::ConversionError>> {
    let input = get_property_unknown(obj, key)?;
    Ok(match input.get_type()? {
        ValueType::String => Ok(String::from_unknown(input)?),
        ValueType::Number
            if invalid == scalar::ConversionError::InvalidDecimal
                && !f64::from_unknown(input)?.is_finite() =>
        {
            Err(scalar::ConversionError::NonFiniteDecimal)
        }
        _ => Err(invalid),
    })
}

fn conversion_error(env: Env, error: scalar::ConversionError) -> Error {
    match env.throw_type_error(&error.to_string(), Some(error.code())) {
        Ok(()) => Error::new(Status::PendingException, error.to_string()),
        Err(error) => error,
    }
}

fn wrapper_to_js(env: sys::napi_env, key: &str, text: String) -> Result<sys::napi_value> {
    let raw_env = Env::from_raw(env);
    let obj = Object::new(&raw_env)?;
    let value = unsafe { String::to_napi_value(env, text) }?;
    define_own_property(&obj, key, value)?;
    unsafe { Object::to_napi_value(env, obj) }
}

/// Internal newtype so recursive positions (array elements, object values)
/// can go through `ToNapiValue` without exposing a blanket recursive impl
/// signature difference.
struct ValueHandle(Value);

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
    use super::{eager_capacity, forbidden_key, MAX_EAGER_CAPACITY};

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
