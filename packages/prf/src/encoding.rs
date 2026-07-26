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
    pub const BYTES: Self = Self("vitaminc/prf/encoding/bytes/v1");
    pub const UTF8: Self = Self("vitaminc/prf/encoding/utf8/v1");
    pub const U8: Self = Self("vitaminc/prf/encoding/u8-le/v1");
    pub const U16: Self = Self("vitaminc/prf/encoding/u16-le/v1");
    pub const U32: Self = Self("vitaminc/prf/encoding/u32-le/v1");
    pub const U64: Self = Self("vitaminc/prf/encoding/u64-le/v1");
    pub const U128: Self = Self("vitaminc/prf/encoding/u128-le/v1");
    pub const I8: Self = Self("vitaminc/prf/encoding/i8-le/v1");
    pub const I16: Self = Self("vitaminc/prf/encoding/i16-le/v1");
    pub const I32: Self = Self("vitaminc/prf/encoding/i32-le/v1");
    pub const I64: Self = Self("vitaminc/prf/encoding/i64-le/v1");
    pub const I128: Self = Self("vitaminc/prf/encoding/i128-le/v1");

    /// Define an application-specific leaf encoding domain.
    ///
    /// Identifiers form part of the cryptographic protocol. Use a stable,
    /// globally namespaced, versioned value such as
    /// `com.example/customer-id/uuid-bytes/v1` and never reuse it for a
    /// different encoding.
    pub const fn new(identifier: &'static str) -> Self {
        assert!(
            !identifier.is_empty(),
            "a PRF encoding domain cannot be empty"
        );
        Self(identifier)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }

    pub const fn as_bytes(self) -> &'static [u8] {
        self.0.as_bytes()
    }
}
