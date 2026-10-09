use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use vitaminc_aead::CipherText;
use vitaminc_aead_napi::{JsCipherText, NapiValue, Value};
use vitaminc_aead_value::transport::{decode_value, encode_value, Reader};
use vitaminc_protected::{Controlled, Protected};

#[napi]
pub fn encode(value: NapiValue) -> napi::Result<Buffer> {
    let mut bytes = Protected::new(Vec::new());
    encode_value(value.0, bytes.risky_inner_mut())
        .map_err(|_| napi::Error::from_reason("transport encode failed"))?;
    Ok(Buffer::from(bytes.risky_ref().to_vec()))
}

/// Convert a JS value to a Rust value and drop it, to test the conversion
/// alone, without the transport encoder's own limits.
#[napi]
pub fn convert(value: NapiValue) {
    drop(value);
}

#[napi]
pub fn decode(bytes: Buffer) -> napi::Result<NapiValue> {
    decode_value(&mut Reader::new(&bytes))
        .map(NapiValue)
        .map_err(|_| napi::Error::from_reason("transport decode failed"))
}

#[napi]
pub fn codec_round_trip(bytes: Buffer) -> napi::Result<Buffer> {
    let value = decode_value(&mut Reader::new(&bytes))
        .map_err(|_| napi::Error::from_reason("transport decode failed"))?;
    let mut encoded = Protected::new(Vec::new());
    encode_value(value, encoded.risky_inner_mut())
        .map_err(|_| napi::Error::from_reason("transport encode failed"))?;
    Ok(Buffer::from(encoded.risky_ref().to_vec()))
}

/// Read a ciphertext node tree into Rust and project it back to JS.
#[napi(ts_return_type = "unknown")]
pub fn ciphertext_round_trip(
    #[napi(ts_arg_type = "unknown")] ct: JsCipherText<Vec<u8>, NapiValue>,
) -> JsCipherText<Vec<u8>, NapiValue> {
    ct
}

/// `levels` containers of one `wrap` kind ("array", "object" or
/// "passthrough") around `true`, built in Rust rather than decoded, so the
/// output conversion's own depth limit is what applies.
#[napi]
pub fn nested_value(levels: u32, wrap: String) -> NapiValue {
    let mut value = Value::Bool(true);
    for _ in 0..levels {
        value = match wrap.as_str() {
            "array" => Value::Array(vec![value]),
            "object" => Value::Object(vec![("k".into(), value)]),
            _ => Value::Passthrough(Box::new(value)),
        };
    }
    NapiValue(value)
}

/// `levels` ciphertext containers of one `wrap` kind ("seq" or "map")
/// around one sealed leaf.
#[napi(ts_return_type = "unknown")]
pub fn nested_ciphertext(levels: u32, wrap: String) -> JsCipherText<Vec<u8>, NapiValue> {
    let mut node = CipherText::Single(vec![0xa1]);
    for _ in 0..levels {
        node = match wrap.as_str() {
            "seq" => CipherText::Sequence(vec![node]),
            _ => CipherText::Map(vec![("k".into(), node)]),
        };
    }
    JsCipherText(node)
}

/// `ct_levels` ciphertext sequences around a passthrough node whose payload
/// is `value_levels` arrays around `true`: one tree whose depth spans both.
#[napi(ts_return_type = "unknown")]
pub fn ciphertext_with_payload(
    ct_levels: u32,
    value_levels: u32,
) -> JsCipherText<Vec<u8>, NapiValue> {
    let NapiValue(payload) = nested_value(value_levels, "array".into());
    let mut node = CipherText::Passthrough(NapiValue(payload));
    for _ in 0..ct_levels {
        node = CipherText::Sequence(vec![node]);
    }
    JsCipherText(node)
}

/// Read a ciphertext node tree into Rust and drop it, to test reading alone.
#[napi]
pub fn read_ciphertext(#[napi(ts_arg_type = "unknown")] ct: JsCipherText<Vec<u8>, NapiValue>) {
    drop(ct);
}

/// As `read_ciphertext`, for a cipher with no passthrough payload.
#[napi]
pub fn read_unit_ciphertext(#[napi(ts_arg_type = "unknown")] ct: JsCipherText<Vec<u8>, ()>) {
    drop(ct);
}

/// `levels` ciphertext sequences around a passthrough node with no payload.
#[napi(ts_return_type = "unknown")]
pub fn unit_ciphertext(levels: u32) -> JsCipherText<Vec<u8>, ()> {
    let mut node = CipherText::Passthrough(());
    for _ in 0..levels {
        node = CipherText::Sequence(vec![node]);
    }
    JsCipherText(node)
}
