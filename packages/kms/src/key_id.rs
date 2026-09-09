/// An opaque, backend-encoded identifier for a previously generated data
/// key. Each implementor decides its own internal shape (ZeroKMS: `iv` +
/// `tag` concatenated; AWS: `CiphertextBlob`; Azure: `(kid, value)`; ...)
/// — callers never need to know which.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
