//! Test addon loaded by `tests/kind_inventory.cjs` in a live Node environment.

use napi::bindgen_prelude::{JsValue, Object};
use napi::{sys, Env, Error, JsError, Result, Status};
use vitaminc_aead_napi::{NapiValue, Value};
use vitaminc_aead_value::ValueKind;
use vitaminc_protected::Protected;

fn sample(kind: ValueKind) -> Result<Value> {
    Ok(match kind {
        ValueKind::Bool => Value::Bool(true),
        ValueKind::Int32 => Value::Int32(-32),
        ValueKind::Int64 => Value::Int64(i64::MIN),
        ValueKind::UInt32 => Value::UInt32(u32::MAX),
        ValueKind::UInt64 => Value::UInt64(u64::MAX),
        ValueKind::Float32 => Value::Float32(1.5),
        ValueKind::Float64 => Value::Float64(2.5),
        ValueKind::String => Value::String("hello".into()),
        ValueKind::Bytes => Value::Bytes(Protected::new(vec![0, 255])),
        ValueKind::Array => Value::Array(vec![Value::Bool(true)]),
        ValueKind::Object => Value::Object(vec![("answer".into(), Value::UInt32(42))]),
        ValueKind::Int8 => Value::Int8(i8::MIN),
        ValueKind::UInt8 => Value::UInt8(u8::MAX),
        ValueKind::Int16 => Value::Int16(i16::MIN),
        ValueKind::UInt16 => Value::UInt16(u16::MAX),
        ValueKind::Int128 => Value::Int128(i128::MIN),
        ValueKind::UInt128 => Value::UInt128(u128::MAX),
        ValueKind::Date => {
            Value::Date(chrono::NaiveDate::from_ymd_opt(2024, 2, 29).expect("valid sample date"))
        }
        ValueKind::Timestamp => Value::Timestamp(chrono::DateTime::UNIX_EPOCH),
        ValueKind::Decimal => Value::Decimal("1.50".parse().expect("valid sample decimal")),
        _ => {
            return Err(Error::new(
                Status::GenericFailure,
                format!("add a Node conversion sample for {kind}"),
            ));
        }
    })
}

fn convert_samples(env: sys::napi_env) -> Result<sys::napi_value> {
    let raw_env = Env::from_raw(env);
    let mut exports = Object::new(&raw_env)?;
    // Drive coverage from the upstream inventory: a newly added kind must
    // have both a sample here and a working production ToNapiValue mapping.
    for &kind in ValueKind::ALL {
        let value = sample(kind)?;
        if value.kind() != Some(kind) {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Node conversion sample has the wrong kind: {kind}"),
            ));
        }
        exports.set(kind.name(), NapiValue(value))?;
    }
    // These variants intentionally have no ValueKind.
    exports.set("null", NapiValue(Value::Null))?;
    exports.set("undefined", NapiValue(Value::Undefined))?;
    exports.set(
        "passthrough",
        NapiValue(Value::Passthrough(Box::new(Value::Bool(true)))),
    )?;
    Ok(exports.raw())
}

/// Load the test samples through the same conversion used by consumer addons.
///
/// # Safety
/// Called by Node with a live environment and exports object on the JS thread.
#[no_mangle]
pub unsafe extern "C" fn napi_register_module_v1(
    env: sys::napi_env,
    _exports: sys::napi_value,
) -> sys::napi_value {
    // The `noop` dev feature disables napi's automatic module registration.
    // Resolve the real host symbols before calling any Node-API function.
    unsafe { sys::setup() };
    match convert_samples(env) {
        Ok(exports) => exports,
        Err(error) => {
            unsafe { JsError::from(error).throw_into(env) };
            std::ptr::null_mut()
        }
    }
}
