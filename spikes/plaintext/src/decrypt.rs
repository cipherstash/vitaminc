//! Decrypt straight to a transport frame, without a `Value` in between.
//!
//! This is the decrypt half of the Go path. The visitor gets each sealed
//! leaf's plaintext, `[tag] ++ payload`, after the AEAD check. For a
//! fixed-width scalar that is already the frame, so it's copied as is.
//! STRING and BYTES only need their length prefix put back.
//!
//! The decrypt data model (`DecipherVisitor`) is already shape-driven and
//! hands over raw leaf bytes, so nothing new is needed on this side. It's
//! the encrypt side that was missing a typed layer.

use vitaminc_aead::{Decipher, DecipherVisitor, Decrypt, IntoAad, MapAccess, SeqAccess, Unspecified};
use vitaminc_aead_value::{tags, transport, Value};
use vitaminc_protected::{Controlled, Protected};

use crate::scalar;

/// A decrypted value, as one transport frame.
pub struct FrameOut(pub Protected<Vec<u8>>);

impl<'c> Decrypt<'c> for FrameOut {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // As with `Value`, the type comes from the ciphertext and the sealed
        // tag, not from the caller.
        decipher.decrypt_any(FrameVisitor, aad)
    }
}

struct FrameVisitor;

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), Unspecified> {
    let len = u32::try_from(len).map_err(|_| Unspecified)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn container(tag: u8, count: usize, body: Protected<Vec<u8>>) -> Result<FrameOut, Unspecified> {
    let mut out = Protected::new(Vec::with_capacity(5 + body.risky_ref().len()));
    out.risky_inner_mut().push(tag);
    write_len(out.risky_inner_mut(), count)?;
    out.risky_inner_mut().extend_from_slice(body.risky_ref());
    Ok(FrameOut(out))
}

impl<'c> DecipherVisitor<'c> for FrameVisitor {
    type Value = FrameOut;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<FrameOut, Unspecified> {
        let bytes = data.risky_ref();
        let (&tag, payload) = bytes.split_first().ok_or(Unspecified)?;
        // Same check the transport decoder makes. Container tags and unknown
        // tags fail it.
        if !scalar::valid(tag, payload) {
            return Err(Unspecified);
        }
        let mut out = Protected::new(Vec::with_capacity(bytes.len() + 4));
        let buf = out.risky_inner_mut();
        buf.push(tag);
        if matches!(tag, tags::STRING | tags::BYTES) {
            write_len(buf, payload.len())?;
        }
        buf.extend_from_slice(payload);
        Ok(FrameOut(out))
        // `data` drops and wipes here.
    }

    fn visit_seq<A: SeqAccess<'c>>(self, mut seq: A) -> Result<FrameOut, Unspecified> {
        let mut body = Protected::new(Vec::new());
        let mut count = 0;
        while let Some(FrameOut(item)) = seq.next_element::<FrameOut>().map_err(|_| Unspecified)? {
            body.risky_inner_mut().extend_from_slice(item.risky_ref());
            count += 1;
        }
        container(transport::ARRAY, count, body)
    }

    fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<FrameOut, Unspecified> {
        let mut body = Protected::new(Vec::new());
        let mut count = 0;
        while let Some(key) = map.next_key().map_err(|_| Unspecified)? {
            let FrameOut(value) = map.next_value::<FrameOut>().map_err(|_| Unspecified)?;
            let buf = body.risky_inner_mut();
            write_len(buf, key.len())?;
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(value.risky_ref());
            count += 1;
        }
        container(transport::OBJECT, count, body)
    }

    fn visit_none(self) -> Result<FrameOut, Unspecified> {
        Ok(FrameOut(Protected::new(vec![tags::NULL])))
    }

    fn visit_passthrough(self, value: Box<dyn std::any::Any + Send + 'static>) -> Result<FrameOut, Unspecified> {
        let value = value.downcast::<Value>().map_err(|_| Unspecified)?;
        let mut out = Protected::new(vec![transport::PASSTHROUGH]);
        transport::encode_value(*value, out.risky_inner_mut()).map_err(|_| Unspecified)?;
        Ok(FrameOut(out))
    }
}
