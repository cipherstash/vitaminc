//! Ciphertext tree to and from transport bytes, with frame passthroughs.
//!
//! Byte-identical to `transport::encode_ciphertext`. A passthrough was
//! always written as an embedded value frame, so carrying it as a frame is a
//! straight copy each way.

use std::collections::HashSet;

use vitaminc_aead::CipherText;
use vitaminc_aead_value::transport::{self, CT_EMPTY_MAP, CT_EMPTY_SEQ, CT_MAP, CT_NONE, CT_PASSTHROUGH, CT_SEQ, CT_SINGLE};

use super::encrypt::{Node, PassthroughFrame};
use crate::sources::frame::{Cursor, FrameError};

pub fn encode<L: AsRef<[u8]>>(node: &Node<L>, out: &mut Vec<u8>) -> Result<(), FrameError> {
    let len = |out: &mut Vec<u8>, n: usize| -> Result<(), FrameError> {
        out.extend_from_slice(&u32::try_from(n).map_err(|_| FrameError)?.to_le_bytes());
        Ok(())
    };
    let leaf = |tag: u8, bytes: &[u8], out: &mut Vec<u8>| -> Result<(), FrameError> {
        out.push(tag);
        len(out, bytes.len())?;
        out.extend_from_slice(bytes);
        Ok(())
    };
    match node {
        CipherText::Single(l) => leaf(CT_SINGLE, l.as_ref(), out)?,
        CipherText::None(l) => leaf(CT_NONE, l.as_ref(), out)?,
        CipherText::EmptySequence(l) => leaf(CT_EMPTY_SEQ, l.as_ref(), out)?,
        CipherText::EmptyMap(l) => leaf(CT_EMPTY_MAP, l.as_ref(), out)?,
        CipherText::Sequence(items) => {
            out.push(CT_SEQ);
            len(out, items.len())?;
            for item in items {
                encode(item, out)?;
            }
        }
        CipherText::Map(entries) => {
            out.push(CT_MAP);
            len(out, entries.len())?;
            for (key, value) in entries {
                len(out, key.len())?;
                out.extend_from_slice(key.as_bytes());
                encode(value, out)?;
            }
        }
        CipherText::Passthrough(PassthroughFrame(frame)) => {
            out.push(CT_PASSTHROUGH);
            out.extend_from_slice(frame);
        }
    }
    Ok(())
}

pub fn decode<L: From<Vec<u8>>>(bytes: &[u8]) -> Result<Node<L>, FrameError> {
    let mut c = Cursor::new(bytes);
    let node = decode_inner(&mut c, 0)?;
    if !c.finished() {
        return Err(FrameError);
    }
    Ok(node)
}

fn decode_inner<L: From<Vec<u8>>>(c: &mut Cursor<'_>, depth: usize) -> Result<Node<L>, FrameError> {
    if depth > transport::MAX_DEPTH {
        return Err(FrameError);
    }
    let leaf = |c: &mut Cursor<'_>| -> Result<L, FrameError> {
        let n = c.count()?;
        Ok(L::from(c.take(n)?.to_vec()))
    };
    Ok(match c.byte()? {
        CT_SINGLE => CipherText::Single(leaf(c)?),
        CT_NONE => CipherText::None(leaf(c)?),
        CT_EMPTY_SEQ => CipherText::EmptySequence(leaf(c)?),
        CT_EMPTY_MAP => CipherText::EmptyMap(leaf(c)?),
        CT_SEQ => {
            let count = c.count()?;
            let mut items = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                items.push(decode_inner(c, depth + 1)?);
            }
            CipherText::Sequence(items)
        }
        CT_MAP => {
            let count = c.count()?;
            let mut entries = Vec::with_capacity(count.min(1024));
            let mut seen = HashSet::new();
            for _ in 0..count {
                let n = c.count()?;
                let key = std::str::from_utf8(c.take(n)?).map_err(|_| FrameError)?.to_owned();
                if !seen.insert(key.clone()) {
                    return Err(FrameError);
                }
                entries.push((key, decode_inner(c, depth + 1)?));
            }
            CipherText::Map(entries)
        }
        // The embedded frame is validated where it sits, one level down.
        CT_PASSTHROUGH => CipherText::Passthrough(PassthroughFrame(c.node(depth + 1)?.as_bytes().to_vec())),
        _ => return Err(FrameError),
    })
}
