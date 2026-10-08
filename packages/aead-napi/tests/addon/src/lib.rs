use napi::{
    bindgen_prelude::{Buffer, FromNapiValue, JsValue, ToNapiValue, Unknown},
    Env,
};
use napi_derive::napi;
use vitaminc_aead_napi::NapiValue;
use vitaminc_aead_value::transport::{decode_value, encode_value, Reader};
use vitaminc_protected::{Controlled, Protected};

#[napi]
pub fn encode(value: Unknown<'_>) -> napi::Result<Buffer> {
    let raw = value.value();
    let value = unsafe { NapiValue::from_napi_value(raw.env, raw.value) }?;
    let mut bytes = Protected::new(Vec::new());
    encode_value(value.0, bytes.risky_inner_mut())
        .map_err(|_| napi::Error::from_reason("transport encode failed"))?;
    Ok(Buffer::from(bytes.risky_ref().to_vec()))
}

#[napi]
pub fn decode(env: Env, bytes: Buffer) -> napi::Result<Unknown<'static>> {
    let value = decode_value(&mut Reader::new(&bytes))
        .map_err(|_| napi::Error::from_reason("transport decode failed"))?;
    let raw = unsafe { NapiValue::to_napi_value(env.raw(), NapiValue(value)) }?;
    unsafe { Unknown::from_napi_value(env.raw(), raw) }
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
