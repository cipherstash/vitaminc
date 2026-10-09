use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use vitaminc_aead_napi::{JsCipherText, NapiValue};
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
