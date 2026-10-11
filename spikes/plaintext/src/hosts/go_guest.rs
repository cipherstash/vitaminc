//! What the vcencrypt wasm guest's `encrypt` and `decrypt` would become.
//!
//! [`today`] is the current `bindings/go/vcencrypt/guest/src/abi.rs` logic,
//! minus the session table and the pointer handling, kept as the reference
//! the tests check against. [`spike`] is the same two functions on the data
//! model. The Go side doesn't change at all: the bytes in and out are the
//! same.

use vitaminc_aead::Context;
use vitaminc_aead_value::transport::{self, Reader};
use vitaminc_aead_value::Value;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Encrypt};
use vitaminc_protected::Protected;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestError {
    /// `STATUS_ENCODING`
    Encoding,
    /// `STATUS_INTERNAL`
    Internal,
    /// `STATUS_AUTH`
    Auth,
}

pub mod today {
    use super::*;

    /// abi.rs `encrypt`: decode the frame into a `Value`, encrypt the `Value`.
    pub fn encrypt(cipher: &Aes256Cipher, aad: &[u8], val: &[u8]) -> Result<Vec<u8>, GuestError> {
        let value = transport::decode_value(&mut Reader::new(val)).map_err(|_| GuestError::Encoding)?;
        let ct: AesCipherText = value
            .encrypt_with_aad(cipher, Context::from_encoded(aad))
            .map_err(|_| GuestError::Internal)?;
        let mut out = Vec::new();
        transport::encode_ciphertext_boxed(ct, &mut out).map_err(|_| GuestError::Encoding)?;
        Ok(out)
    }

    /// abi.rs `decrypt`: decrypt to a `Value`, encode the `Value`.
    pub fn decrypt(cipher: &Aes256Cipher, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, GuestError> {
        let ct: AesCipherText =
            transport::decode_ciphertext_boxed(&mut Reader::new(ct)).map_err(|_| GuestError::Encoding)?;
        let value: Value = cipher
            .decrypt_with_aad(ct, Context::from_encoded(aad))
            .map_err(|_| GuestError::Auth)?;
        let mut out = Vec::new();
        transport::encode_value(value, &mut out).map_err(|_| GuestError::Encoding)?;
        Ok(out)
    }
}

/// The same two functions on the data model. No `Value` anywhere,
/// including passthrough. Encrypt walks the frame in place; decrypt writes
/// the frame directly through `decrypt_into(.., FrameWriter)`.
pub mod spike {
    use super::*;
    use crate::{codec, decrypt_into, DecryptError, Frame, FrameWriter};
    use vitaminc_aead::LocalCipherText;
    use vitaminc_protected::Controlled;

    pub fn encrypt(cipher: &Aes256Cipher, aad: &[u8], val: &[u8]) -> Result<Vec<u8>, GuestError> {
        let frame = Frame::parse(val).map_err(|_| GuestError::Encoding)?;
        let ct = crate::encrypt(frame, cipher, Context::from_encoded(aad)).map_err(|_| GuestError::Internal)?;
        let mut out = Vec::new();
        codec::encode(&ct, &mut out).map_err(|_| GuestError::Encoding)?;
        Ok(out)
    }

    pub fn decrypt(cipher: &Aes256Cipher, aad: &[u8], ct: &[u8]) -> Result<Protected<Vec<u8>>, GuestError> {
        let node = codec::decode::<LocalCipherText>(ct).map_err(|_| GuestError::Encoding)?;
        let mut out = Protected::new(Vec::new());
        decrypt_into(cipher, node, Context::from_encoded(aad), FrameWriter::new(out.risky_inner_mut())).map_err(
            |e| match e {
                DecryptError::Auth => GuestError::Auth,
                _ => GuestError::Encoding,
            },
        )?;
        Ok(out)
    }
}
