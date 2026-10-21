//! The self-describing binary encoding that carries an Azure Key Vault key
//! identifier alongside the AES-GCM output the vault produced.
//!
//! Azure returns two things from `encrypt`: the `kid` of the exact key
//! *version* that did the work, and the resulting bytes. Both are needed to
//! reverse the operation, because `decrypt` takes the version as a path
//! segment and Azure rotates a key's current version underneath a caller
//! that only names the key. `A256GCM` also needs the IV and the tag again on
//! `decrypt`. So the adapter keeps all four together in one opaque blob,
//! which becomes the [`KeyId`](crate::KeyId) of a data key and the
//! ciphertext of [`EncryptWithKey`](crate::EncryptWithKey).
//!
//! # Wire format
//!
//! All integers are big-endian. There is a leading format byte so a later
//! format can be told apart from this one rather than silently misread.
//!
//! ```text
//! offset  size  field
//! 0       1     format version, currently 1
//! 1       2     kid length, in bytes
//! 3       n     kid, UTF-8 — the vault's full key identifier, e.g.
//!               https://my-vault.vault.azure.net/keys/my-key/<version>
//! 3+n     2     value length, in bytes
//! 5+n     m     value — the AES-GCM ciphertext
//! 5+n+m   1     IV length, in bytes
//!         i     IV
//!         1     authentication tag length, in bytes
//!         t     authentication tag
//! ```
//!
//! The kid and value lengths are `u16`, because a `kid` is a URL and an
//! encrypted 256-bit key or a small direct-encryption ciphertext is at most
//! a few hundred bytes. Anything longer is a bug, not a payload, and is
//! rejected on the way in.

use std::fmt;

const FORMAT_V1: u8 = 1;
const HEADER_LEN: usize = 3;

/// A key identifier plus the AES-GCM output the vault produced under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Envelope {
    /// The full `kid` the vault returned, including the key version.
    pub(super) kid: String,
    /// The AES-GCM ciphertext.
    pub(super) value: Vec<u8>,
    /// The AES-GCM initialization vector.
    pub(super) iv: Vec<u8>,
    /// The AES-GCM authentication tag.
    pub(super) tag: Vec<u8>,
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
        }
    }
}

impl Envelope {
    pub(super) fn new(kid: String, value: Vec<u8>, iv: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            kid,
            value,
            iv,
            tag,
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let kid_len = u16::try_from(self.kid.len())
            .map_err(|_| EnvelopeError::FieldTooLong("key identifier"))?;
        let value_len =
            u16::try_from(self.value.len()).map_err(|_| EnvelopeError::FieldTooLong("value"))?;
        let iv_len = u8::try_from(self.iv.len()).map_err(|_| EnvelopeError::FieldTooLong("IV"))?;
        let tag_len = u8::try_from(self.tag.len())
            .map_err(|_| EnvelopeError::FieldTooLong("authentication tag"))?;

        let mut out = Vec::with_capacity(
            HEADER_LEN + self.kid.len() + 2 + self.value.len() + 2 + self.iv.len() + self.tag.len(),
        );
        out.push(FORMAT_V1);
        out.extend_from_slice(&kid_len.to_be_bytes());
        out.extend_from_slice(self.kid.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(&self.value);
        out.push(iv_len);
        out.extend_from_slice(&self.iv);
        out.push(tag_len);
        out.extend_from_slice(&self.tag);
        Ok(out)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut reader = Reader::new(bytes);

        match reader.u8()? {
            FORMAT_V1 => {}
            other => return Err(EnvelopeError::UnknownFormat(other)),
        }

        let kid_len = reader.u16()? as usize;
        let kid = std::str::from_utf8(reader.take(kid_len)?)
            .map_err(|_| EnvelopeError::KidNotUtf8)?
            .to_owned();

        let value_len = reader.u16()? as usize;
        let value = reader.take(value_len)?.to_vec();

        let iv_len = reader.u8()? as usize;
        let iv = reader.take(iv_len)?.to_vec();
        let tag_len = reader.u8()? as usize;
        let tag = reader.take(tag_len)?.to_vec();

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

    fn envelope(kid: &str, value: Vec<u8>) -> Envelope {
        Envelope::new(kid.to_owned(), value, vec![2u8; 12], vec![3u8; 16])
    }

    #[test]
    fn an_envelope_round_trips_with_its_iv_and_tag() {
        let envelope = Envelope::new(KID.to_owned(), vec![1u8; 13], vec![2u8; 12], vec![3u8; 16]);
        let encoded = envelope.encode().unwrap();

        assert_eq!(encoded[0], FORMAT_V1);
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.iv, vec![2u8; 12]);
        assert_eq!(decoded.tag, vec![3u8; 16]);
    }

    #[test]
    fn the_kid_survives_the_round_trip_verbatim() {
        let encoded = envelope(KID, vec![9u8; 4]).encode().unwrap();
        assert_eq!(Envelope::decode(&encoded).unwrap().kid, KID);
    }

    #[test]
    fn an_unknown_format_byte_is_rejected_rather_than_misread() {
        let mut encoded = envelope(KID, vec![0u8; 8]).encode().unwrap();
        encoded[0] = 2;
        assert_eq!(
            Envelope::decode(&encoded),
            Err(EnvelopeError::UnknownFormat(2))
        );
    }

    #[test]
    fn a_truncated_envelope_is_rejected() {
        let encoded = envelope(KID, vec![0u8; 8]).encode().unwrap();
        assert_eq!(
            Envelope::decode(&encoded[..encoded.len() - 1]),
            Err(EnvelopeError::Truncated)
        );
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn an_envelope_without_its_iv_and_tag_is_rejected() {
        // The bytes up to the end of the value, and nothing after. The IV
        // and the tag are not optional.
        let encoded = envelope(KID, vec![0u8; 8]).encode().unwrap();
        let without_iv_and_tag = &encoded[..HEADER_LEN + KID.len() + 2 + 8];
        assert_eq!(
            Envelope::decode(without_iv_and_tag),
            Err(EnvelopeError::Truncated)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = envelope(KID, vec![0u8; 8]).encode().unwrap();
        encoded.push(0);
        assert_eq!(
            Envelope::decode(&encoded),
            Err(EnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn every_error_says_what_is_wrong_with_the_bytes() {
        let cases = [
            (EnvelopeError::Truncated, "ends before"),
            (EnvelopeError::TrailingBytes, "bytes after"),
            (EnvelopeError::UnknownFormat(7), "format byte is 7"),
            (EnvelopeError::KidNotUtf8, "not UTF-8"),
            (EnvelopeError::FieldTooLong("IV"), "its IV is too long"),
        ];

        for (error, expected) in cases {
            let message = error.to_string();
            assert!(
                message.contains(expected),
                "{error:?} reads {message:?}, which does not mention {expected:?}"
            );
        }
    }

    #[test]
    fn a_kid_longer_than_its_length_prefix_is_rejected() {
        let envelope = envelope(&"k".repeat(usize::from(u16::MAX) + 1), vec![0u8; 4]);
        assert_eq!(
            envelope.encode(),
            Err(EnvelopeError::FieldTooLong("key identifier"))
        );
    }
}
