use vitaminc_aead_value::FfiValue;

/// Newtype over [`FfiValue`] carrying the Node.js conversions.
///
/// The value tree itself — and its `Encrypt`/`Decrypt` impls and leaf wire
/// format — lives in the language-neutral `vitaminc-aead-value` crate. This
/// wrapper exists because Rust's orphan rule prevents implementing napi's
/// `FromNapiValue`/`ToNapiValue` (foreign traits) directly on `FfiValue`
/// (a foreign type) from this crate.
///
/// Convert with [`From`]/[`Into`] (or [`into_inner`](NapiValue::into_inner))
/// at the `#[napi]` function boundary; everything past that boundary works
/// with the bare [`FfiValue`].
///
/// See the `vitaminc-aead-value` crate docs for the JS type mapping,
/// including the `Number`/`Int` split (JS numbers always encode as
/// `Number`; `BigInt` encodes as `Int`) and the `BigInt` decode rule.
pub struct NapiValue(pub FfiValue);

impl NapiValue {
    /// Unwrap to the language-neutral value tree.
    pub fn into_inner(self) -> FfiValue {
        self.0
    }
}

impl From<FfiValue> for NapiValue {
    fn from(value: FfiValue) -> Self {
        NapiValue(value)
    }
}

impl From<NapiValue> for FfiValue {
    fn from(value: NapiValue) -> Self {
        value.0
    }
}
