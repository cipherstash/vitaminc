use vitaminc_protected::OpaqueDebug;

/// An opaque, backend-encoded identifier for a previously generated data
/// key. Each implementor decides its own internal shape (ZeroKMS: `iv` +
/// `tag` concatenated; AWS: `CiphertextBlob`; Azure: `(kid, value)`; ...)
/// — callers never need to know which.
///
/// For every backend in this crate the bytes *are* the data key, under
/// encryption. A source says which it hands back through
/// [`CUSTODY`](crate::RetrieveDataKey::CUSTODY), and a
/// [`ClientHeld`](crate::KeyCustody::ClientHeld) key id is the only copy of
/// that key: store it durably, because losing it loses the data, and treat it
/// as key material when deciding where it may be copied.
///
/// `Debug` is opaque for that reason. The bytes are already encrypted, so
/// printing them is not a plaintext leak, but this is the one handle in the
/// crate that carries key material in any form, and it should not reach a log
/// by default. An implementor that needs the encoding calls
/// [`as_bytes`](Self::as_bytes).
#[derive(Clone, PartialEq, Eq, Hash, OpaqueDebug)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    /// Construct a `KeyId` from a backend-specific encoding.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The backend-specific encoding, for an implementor to decode.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KeyId {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyId;

    /// The bytes are the data key under encryption for every backend in this
    /// crate, so `Debug` must not print them — see the type's docs.
    #[test]
    fn debug_does_not_print_the_bytes() {
        let id = KeyId::new(b"wrapped-key-material".to_vec());
        let shown = format!("{id:?}");
        assert!(!shown.contains("wrapped"), "{shown}");
        assert!(!shown.contains("119"), "{shown}");
        assert!(shown.contains("***"), "{shown}");
    }

    /// Masking `Debug` must not cost the encoding an implementor needs.
    #[test]
    fn the_encoding_is_still_reachable() {
        let id = KeyId::new(vec![1, 2, 3]);
        assert_eq!(id.as_bytes(), &[1, 2, 3]);
    }
}
