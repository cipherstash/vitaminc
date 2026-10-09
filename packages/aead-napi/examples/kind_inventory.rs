//! Test addon loaded by `tests/kind_inventory.cjs` in a live Node environment.

use napi::bindgen_prelude::{Object, ToNapiValue};
use napi::{sys, Env, Error, JsError, Result, Status};
use vitaminc_aead_napi::{NapiValue, Value};
use vitaminc_aead_value::ValueKind;
use vitaminc_protected::Protected;

fn sample(kind: ValueKind) -> Result<Option<Value>> {
    Ok(Some(match kind {
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
        // The Node mappings for these kinds land with #375. Listing them keeps
        // any other new kind failing below until it has a sample.
        ValueKind::Int8
        | ValueKind::UInt8
        | ValueKind::Int16
        | ValueKind::UInt16
        | ValueKind::Int128
        | ValueKind::UInt128
        | ValueKind::Date
        | ValueKind::Timestamp
        | ValueKind::Decimal => return Ok(None),
        _ => {
            return Err(Error::new(
                Status::GenericFailure,
                format!("add a Node conversion sample for {kind}"),
            ));
        }
    }))
}

fn convert_samples(env: sys::napi_env) -> Result<sys::napi_value> {
    let raw_env = Env::from_raw(env);
    let mut exports = Object::new(&raw_env)?;
    // Drive coverage from the upstream inventory: a newly added kind must
    // have both a sample here and a working production ToNapiValue mapping.
    for &kind in ValueKind::ALL {
        let Some(value) = sample(kind)? else {
            continue;
        };
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
    unsafe { Object::to_napi_value(env, exports) }
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
