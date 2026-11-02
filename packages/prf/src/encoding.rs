/// A stable semantic domain for encoding a protected PRF leaf.
///
/// The domain is framed alongside the context and protected bytes, preventing
/// values with identical byte representations but different meanings from
/// deriving the same block. Multiple Rust containers may deliberately share a
/// domain when they represent the same semantic value; all byte containers,
/// for example, use [`BYTES`](Self::BYTES).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrfEncoding(&'static str);

impl PrfEncoding {
    /// Opaque byte sequences, shared by fixed and variable-length byte containers.
    pub const BYTES: Self = Self("vitaminc/prf/encoding/bytes/v1");
    /// UTF-8 text, distinct from byte sequences with identical bytes.
    pub const UTF8: Self = Self("vitaminc/prf/encoding/utf8/v1");
    /// Unsigned 8-bit integers in little-endian encoding; distinct from other widths.
    pub const U8: Self = Self("vitaminc/prf/encoding/u8-le/v1");
    /// Unsigned 16-bit integers in little-endian encoding; distinct from other widths.
    pub const U16: Self = Self("vitaminc/prf/encoding/u16-le/v1");
    /// Unsigned 32-bit integers in little-endian encoding; distinct from other widths.
    pub const U32: Self = Self("vitaminc/prf/encoding/u32-le/v1");
    /// Unsigned 64-bit integers in little-endian encoding; distinct from other widths.
    pub const U64: Self = Self("vitaminc/prf/encoding/u64-le/v1");
    /// Unsigned 128-bit integers in little-endian encoding; distinct from other widths.
    pub const U128: Self = Self("vitaminc/prf/encoding/u128-le/v1");
    /// Signed 8-bit integers in little-endian encoding; distinct from other widths.
    pub const I8: Self = Self("vitaminc/prf/encoding/i8-le/v1");
    /// Signed 16-bit integers in little-endian encoding; distinct from other widths.
    pub const I16: Self = Self("vitaminc/prf/encoding/i16-le/v1");
    /// Signed 32-bit integers in little-endian encoding; distinct from other widths.
    pub const I32: Self = Self("vitaminc/prf/encoding/i32-le/v1");
    /// Signed 64-bit integers in little-endian encoding; distinct from other widths.
    pub const I64: Self = Self("vitaminc/prf/encoding/i64-le/v1");
    /// Signed 128-bit integers in little-endian encoding; distinct from other widths.
    pub const I128: Self = Self("vitaminc/prf/encoding/i128-le/v1");

    /// Define an application-specific leaf encoding domain.
    ///
    /// Identifiers form part of the cryptographic protocol. Use a stable,
    /// globally namespaced, versioned value such as
    /// `com.example/customer-id/uuid-bytes/v1` and never reuse it for a
    /// different encoding.
    ///
    /// # Panics
    ///
    /// Panics if `identifier` is empty. No other namespace validation is performed.
    ///
    /// # Examples
    ///
    /// ```
    /// use vitaminc_prf::PrfEncoding;
    /// let domain = PrfEncoding::new("com.example/customer-id/v1");
    /// assert_eq!(domain.as_bytes(), b"com.example/customer-id/v1");
    /// assert_ne!(PrfEncoding::BYTES, PrfEncoding::UTF8);
    /// ```
    pub const fn new(identifier: &'static str) -> Self {
        assert!(
            !identifier.is_empty(),
            "a PRF encoding domain cannot be empty"
        );
        Self(identifier)
    }

    /// The stable domain identifier, without additional framing.
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// UTF-8 bytes of the stable domain identifier, without framing.
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::PrfEncoding;

    #[test]
    fn string_and_byte_views_preserve_the_identifier() {
        let encoding = PrfEncoding::new("com.example/test-value/v1");
        assert_eq!(encoding.as_str(), "com.example/test-value/v1");
        assert_eq!(encoding.as_bytes(), b"com.example/test-value/v1");
    }
}
