//! The self-describing binary encoding that carries an Azure Key Vault key
//! identifier alongside the bytes the vault produced.
//!
//! Azure returns two things from `wrapKey` and `encrypt`: the `kid` of the
//! exact key *version* that did the work, and the resulting bytes. Both are
//! needed to reverse the operation, because `unwrapKey` and `decrypt` take
//! the version as a path segment and Azure rotates a key's current version
//! underneath a caller that only names the key. So the adapter keeps them
//! together in one opaque blob, which becomes the
//! [`KeyId`](crate::KeyId) of a data key and the ciphertext of
//! [`EncryptWithKey`](crate::EncryptWithKey).
//!
//! # Wire format
//!
//! All integers are big-endian. There is a leading format byte so a later
//! format can be told apart from this one rather than silently misread.
//!
//! ```text
//! offset  size  field
//! 0       1     format version, currently 1
//! 1       1     flags; bit 0 set when an IV and a tag follow (AES-GCM)
//! 2       2     kid length, in bytes
//! 4       n     kid, UTF-8 — the vault's full key identifier, e.g.
//!               https://my-vault.vault.azure.net/keys/my-key/<version>
//! 4+n     2     value length, in bytes
//! 6+n     m     value — the wrapped key, or the ciphertext
//!
//! then, only when flags bit 0 is set:
//!         1     IV length, in bytes
//!         i     IV
//!         1     authentication tag length, in bytes
//!         t     authentication tag
//! ```
//!
//! The lengths are `u16` because a `kid` is a URL and a wrapped 256-bit key
//! or a small direct-encryption ciphertext is at most a few hundred bytes;
//! anything longer is a bug, not a payload, and is rejected on the way in.

use std::fmt;

const FORMAT_V1: u8 = 1;
const FLAG_AEAD: u8 = 0b0000_0001;
const HEADER_LEN: usize = 4;

/// A key identifier plus the bytes the vault produced under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Envelope {
    /// The full `kid` the vault returned, including the key version.
    pub(super) kid: String,
    /// The wrapped key or the ciphertext.
    pub(super) value: Vec<u8>,
    /// The AES-GCM initialization vector, when the value is AEAD ciphertext.
    pub(super) iv: Option<Vec<u8>>,
    /// The AES-GCM authentication tag, when the value is AEAD ciphertext.
    pub(super) tag: Option<Vec<u8>>,
}

/// Why an [`Envelope`] could not be encoded or decoded. Kept crate-private:
/// each adapter folds it into its own public error as a message, so the
/// wire format stays an implementation detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum EnvelopeError {
    /// Fewer bytes than the declared lengths need.
    Truncated,
    /// Trailing bytes after the last declared field.
    TrailingBytes,
    /// A format byte this version of the crate does not know.
    UnknownFormat(u8),
    /// The kid bytes are not UTF-8.
    KidNotUtf8,
    /// A field is longer than its length prefix can express.
    FieldTooLong(&'static str),
    /// The AEAD flag and the presence of an IV and a tag disagree.
    InconsistentAead,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("it ends before its declared fields do"),
            Self::TrailingBytes => f.write_str("it has bytes after its last declared field"),
            Self::UnknownFormat(byte) => {
                write!(f, "its format byte is {byte}, and only format 1 is known")
            }
            Self::KidNotUtf8 => f.write_str("its key identifier is not UTF-8"),
            Self::FieldTooLong(field) => write!(f, "its {field} is too long to encode"),
            Self::InconsistentAead => {
                f.write_str("it sets the AEAD flag without both an IV and a tag, or the reverse")
            }
        }
    }
}

impl Envelope {
    /// An envelope over a wrapped key or a non-AEAD ciphertext.
    pub(super) fn plain(kid: String, value: Vec<u8>) -> Self {
        Self {
            kid,
            value,
            iv: None,
            tag: None,
        }
    }

    /// An envelope over AES-GCM ciphertext.
    pub(super) fn aead(kid: String, value: Vec<u8>, iv: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            kid,
            value,
            iv: Some(iv),
            tag: Some(tag),
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let (flags, iv, tag) = match (&self.iv, &self.tag) {
            (None, None) => (0u8, &[][..], &[][..]),
            (Some(iv), Some(tag)) => (FLAG_AEAD, iv.as_slice(), tag.as_slice()),
            _ => return Err(EnvelopeError::InconsistentAead),
        };

        let kid_len = u16::try_from(self.kid.len())
            .map_err(|_| EnvelopeError::FieldTooLong("key identifier"))?;
        let value_len =
            u16::try_from(self.value.len()).map_err(|_| EnvelopeError::FieldTooLong("value"))?;
        let iv_len = u8::try_from(iv.len()).map_err(|_| EnvelopeError::FieldTooLong("IV"))?;
        let tag_len = u8::try_from(tag.len())
            .map_err(|_| EnvelopeError::FieldTooLong("authentication tag"))?;

        let mut out = Vec::with_capacity(
            HEADER_LEN + self.kid.len() + 2 + self.value.len() + 2 + iv.len() + tag.len(),
        );
        out.push(FORMAT_V1);
        out.push(flags);
        out.extend_from_slice(&kid_len.to_be_bytes());
        out.extend_from_slice(self.kid.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(&self.value);
        if flags & FLAG_AEAD != 0 {
            out.push(iv_len);
            out.extend_from_slice(iv);
            out.push(tag_len);
            out.extend_from_slice(tag);
        }
        Ok(out)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut reader = Reader::new(bytes);

        match reader.u8()? {
            FORMAT_V1 => {}
            other => return Err(EnvelopeError::UnknownFormat(other)),
        }
        let flags = reader.u8()?;

        let kid_len = reader.u16()? as usize;
        let kid = std::str::from_utf8(reader.take(kid_len)?)
            .map_err(|_| EnvelopeError::KidNotUtf8)?
            .to_owned();

        let value_len = reader.u16()? as usize;
        let value = reader.take(value_len)?.to_vec();

        let (iv, tag) = if flags & FLAG_AEAD != 0 {
            let iv_len = reader.u8()? as usize;
            let iv = reader.take(iv_len)?.to_vec();
            let tag_len = reader.u8()? as usize;
            let tag = reader.take(tag_len)?.to_vec();
            (Some(iv), Some(tag))
        } else {
            (None, None)
        };

        if !reader.is_empty() {
            return Err(EnvelopeError::TrailingBytes);
        }

        Ok(Self {
            kid,
            value,
            iv,
            tag,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvelopeError> {
        if self.0.len() < n {
            return Err(EnvelopeError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, EnvelopeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "https://my-vault.vault.azure.net/keys/my-key/0123456789abcdef";

    #[test]
    fn a_plain_envelope_round_trips() {
        let envelope = Envelope::plain(KID.to_owned(), vec![7u8; 40]);
        let encoded = envelope.encode().unwrap();

        assert_eq!(encoded[0], FORMAT_V1);
        assert_eq!(encoded[1], 0);
        assert_eq!(Envelope::decode(&encoded).unwrap(), envelope);
    }

    #[test]
    fn an_aead_envelope_round_trips_with_its_iv_and_tag() {
        let envelope = Envelope::aead(KID.to_owned(), vec![1u8; 13], vec![2u8; 12], vec![3u8; 16]);
        let encoded = envelope.encode().unwrap();

        assert_eq!(encoded[1], FLAG_AEAD);
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.iv.unwrap(), vec![2u8; 12]);
        assert_eq!(decoded.tag.unwrap(), vec![3u8; 16]);
    }

    #[test]
    fn the_kid_survives_the_round_trip_verbatim() {
        let encoded = Envelope::plain(KID.to_owned(), vec![9u8; 4])
            .encode()
            .unwrap();
        assert_eq!(Envelope::decode(&encoded).unwrap().kid, KID);
    }

    #[test]
    fn an_unknown_format_byte_is_rejected_rather_than_misread() {
        let mut encoded = Envelope::plain(KID.to_owned(), vec![0u8; 8])
            .encode()
            .unwrap();
        encoded[0] = 2;
        assert_eq!(
            Envelope::decode(&encoded),
            Err(EnvelopeError::UnknownFormat(2))
        );
    }

    #[test]
    fn a_truncated_envelope_is_rejected() {
        let encoded = Envelope::plain(KID.to_owned(), vec![0u8; 8])
            .encode()
            .unwrap();
        assert_eq!(
            Envelope::decode(&encoded[..encoded.len() - 1]),
            Err(EnvelopeError::Truncated)
        );
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Envelope::plain(KID.to_owned(), vec![0u8; 8])
            .encode()
            .unwrap();
        encoded.push(0);
        assert_eq!(
            Envelope::decode(&encoded),
            Err(EnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn a_half_aead_envelope_cannot_be_encoded() {
        let envelope = Envelope {
            kid: KID.to_owned(),
            value: vec![0u8; 8],
            iv: Some(vec![0u8; 12]),
            tag: None,
        };
        assert_eq!(envelope.encode(), Err(EnvelopeError::InconsistentAead));
    }

    #[test]
    fn a_kid_longer_than_its_length_prefix_is_rejected() {
        let envelope = Envelope::plain("k".repeat(usize::from(u16::MAX) + 1), vec![0u8; 4]);
        assert_eq!(
            envelope.encode(),
            Err(EnvelopeError::FieldTooLong("key identifier"))
        );
    }
}
