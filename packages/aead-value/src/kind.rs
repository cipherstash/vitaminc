//! Value kinds — the FFI type vocabulary, without a value.
//!
//! A binding for a dynamically typed host (JavaScript, PHP, Ruby) often has
//! to say what a field's values *are* before it has one: "this field holds
//! `uint64`s", not "here is a `34`". [`ValueKind`] is that declaration. It is
//! the [`Value`] model with the payload taken away: one kind per scalar
//! tag family in [`tags`] (two tags for `bool`, whose value is its tag) plus
//! the two containers, [`Array`](ValueKind::Array) and
//! [`Object`](ValueKind::Object).
//!
//! # What is not a kind
//!
//! - **`Null` and `Undefined`.** They are tagged leaves, but each is a type
//!   with exactly one value, so declaring a field as one says nothing a
//!   binding could use. A field declared with a kind is a field whose values
//!   are of that kind; whether it may also be absent is the declaring
//!   layer's business, not this vocabulary's.
//! - **`Passthrough`.** It is a transport choice (send this subtree in the
//!   clear), not a type: the wrapped value has a kind of its own.
//!
//! So [`Value::kind`] is `None` for those three variants, and no kind
//! [`holds`](ValueKind::holds) them.
//!
//! # Names are wire format
//!
//! [`ValueKind::name`] (also its [`Display`](fmt::Display) and
//! [`FromStr`] form) is how a binding spells a kind in a
//! declaration that crosses the FFI boundary. Like the tag table, the names
//! are frozen: they are matched exactly, case-sensitively, and are never
//! renamed. A new kind takes a new name.
//!
//! This module defines the vocabulary only. Rules over it — which numeric
//! kinds convert into which, which kinds an index is defined for — belong to
//! the layer that declares fields, not here.
//!
//! ```
//! use vitaminc_aead_value::{Value, ValueKind};
//!
//! let kind: ValueKind = "uint64".parse().unwrap();
//! assert_eq!(kind, ValueKind::UInt64);
//! assert!(kind.holds(&Value::UInt64(34)));
//! assert!(!kind.holds(&Value::Float64(34.0)));
//! assert_eq!(Value::UInt64(34).kind(), Some(ValueKind::UInt64));
//! assert_eq!(Value::Null.kind(), None);
//! ```

use std::fmt;
use std::str::FromStr;

use crate::{tags, Value};

/// The kind of a [`Value`]: its variant, without a payload.
///
/// This is the type vocabulary a binding declares a field with. See the
/// [module docs](self) for why `Null`, `Undefined` and `Passthrough` have no
/// kind, and why [`name`](Self::name) is frozen.
///
/// Non-exhaustive so future kinds can be added; downstream matches must
/// handle unsupported kinds. Names and tags for optional chrono/decimal
/// payloads remain available even when their cargo features are disabled.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ValueKind {
    /// `"bool"`: [`Value::Bool`], tags [`BOOL_FALSE`](tags::BOOL_FALSE)
    /// and [`BOOL_TRUE`](tags::BOOL_TRUE).
    Bool,
    /// `"int32"`: [`Value::Int32`], tag [`INT32`](tags::INT32).
    Int32,
    /// `"int64"`: [`Value::Int64`], tag [`INT64`](tags::INT64).
    Int64,
    /// `"uint32"`: [`Value::UInt32`], tag [`UINT32`](tags::UINT32).
    UInt32,
    /// `"uint64"`: [`Value::UInt64`], tag [`UINT64`](tags::UINT64).
    UInt64,
    /// `"float32"`: [`Value::Float32`], tag [`FLOAT32`](tags::FLOAT32).
    Float32,
    /// `"float64"`: [`Value::Float64`], tag [`FLOAT64`](tags::FLOAT64).
    Float64,
    /// `"string"`: [`Value::String`], tag [`STRING`](tags::STRING).
    String,
    /// `"bytes"`: [`Value::Bytes`], tag [`BYTES`](tags::BYTES).
    Bytes,
    /// `"int8"`, tag [`INT8`](tags::INT8).
    Int8,
    /// `"uint8"`, tag [`UINT8`](tags::UINT8).
    UInt8,
    /// `"int16"`, tag [`INT16`](tags::INT16).
    Int16,
    /// `"uint16"`, tag [`UINT16`](tags::UINT16).
    UInt16,
    /// `"int128"`, tag [`INT128`](tags::INT128).
    Int128,
    /// `"uint128"`, tag [`UINT128`](tags::UINT128).
    UInt128,
    /// `"date"`, tag [`DATE`](tags::DATE).
    Date,
    /// `"timestamp"`, tag [`TIMESTAMP`](tags::TIMESTAMP).
    Timestamp,
    /// `"decimal"`, tag [`DECIMAL`](tags::DECIMAL).
    Decimal,
    /// `"array"`: [`Value::Array`], sealed in the cipher's sequence mode
    /// with no tag of its own. Says nothing about the elements' kinds.
    Array,
    /// `"object"`: [`Value::Object`], sealed in the cipher's map mode
    /// with no tag of its own. Says nothing about the entries' kinds.
    Object,
}

impl ValueKind {
    /// Every kind, in declaration order.
    pub const ALL: [ValueKind; 20] = [
        ValueKind::Bool,
        ValueKind::Int32,
        ValueKind::Int64,
        ValueKind::UInt32,
        ValueKind::UInt64,
        ValueKind::Float32,
        ValueKind::Float64,
        ValueKind::String,
        ValueKind::Bytes,
        ValueKind::Int8,
        ValueKind::UInt8,
        ValueKind::Int16,
        ValueKind::UInt16,
        ValueKind::Int128,
        ValueKind::UInt128,
        ValueKind::Date,
        ValueKind::Timestamp,
        ValueKind::Decimal,
        ValueKind::Array,
        ValueKind::Object,
    ];

    /// The exact lowercase name used in declarations, e.g. `"int16"`,
    /// `"timestamp"` or `"decimal"`. Frozen wire format.
    pub const fn name(self) -> &'static str {
        match self {
            ValueKind::Bool => "bool",
            ValueKind::Int32 => "int32",
            ValueKind::Int64 => "int64",
            ValueKind::UInt32 => "uint32",
            ValueKind::UInt64 => "uint64",
            ValueKind::Float32 => "float32",
            ValueKind::Float64 => "float64",
            ValueKind::String => "string",
            ValueKind::Bytes => "bytes",
            ValueKind::Int8 => "int8",
            ValueKind::UInt8 => "uint8",
            ValueKind::Int16 => "int16",
            ValueKind::UInt16 => "uint16",
            ValueKind::Int128 => "int128",
            ValueKind::UInt128 => "uint128",
            ValueKind::Date => "date",
            ValueKind::Timestamp => "timestamp",
            ValueKind::Decimal => "decimal",
            ValueKind::Array => "array",
            ValueKind::Object => "object",
        }
    }

    /// The [`tags`] a value of this kind seals under: one per scalar kind,
    /// two for [`Bool`](Self::Bool) (the value is the tag), and none for
    /// [`Array`](Self::Array) or [`Object`](Self::Object), which seal as
    /// structure rather than as a tagged leaf.
    pub const fn tags(self) -> &'static [u8] {
        match self {
            ValueKind::Bool => &[tags::BOOL_FALSE, tags::BOOL_TRUE],
            ValueKind::Int32 => &[tags::INT32],
            ValueKind::Int64 => &[tags::INT64],
            ValueKind::UInt32 => &[tags::UINT32],
            ValueKind::UInt64 => &[tags::UINT64],
            ValueKind::Float32 => &[tags::FLOAT32],
            ValueKind::Float64 => &[tags::FLOAT64],
            ValueKind::String => &[tags::STRING],
            ValueKind::Bytes => &[tags::BYTES],
            ValueKind::Int8 => &[tags::INT8],
            ValueKind::UInt8 => &[tags::UINT8],
            ValueKind::Int16 => &[tags::INT16],
            ValueKind::UInt16 => &[tags::UINT16],
            ValueKind::Int128 => &[tags::INT128],
            ValueKind::UInt128 => &[tags::UINT128],
            ValueKind::Date => &[tags::DATE],
            ValueKind::Timestamp => &[tags::TIMESTAMP],
            ValueKind::Decimal => &[tags::DECIMAL],
            ValueKind::Array | ValueKind::Object => &[],
        }
    }

    /// Whether `value` is of this kind. Exact: an `Int64` is not held by
    /// [`UInt64`](Self::UInt64), and a [`Value::Passthrough`] is held by
    /// no kind, whatever it wraps.
    pub fn holds(self, value: &Value) -> bool {
        value.kind() == Some(self)
    }
}

impl fmt::Display for ValueKind {
    /// Writes [`name`](Self::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ValueKind {
    type Err = ParseValueKindError;

    /// Parses a [`name`](Self::name), exactly: `"uint64"`, not `"UInt64"`,
    /// `"u64"` or `" uint64"`. `"null"` and `"undefined"` are not kinds.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        ValueKind::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
            .ok_or(ParseValueKindError)
    }
}

/// The error from parsing a string that is not a [`ValueKind::name`].
///
/// Carries no detail: the caller holds the string it tried to parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParseValueKindError;

impl fmt::Display for ParseValueKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a value kind")
    }
}

impl std::error::Error for ParseValueKindError {}

impl Value {
    /// This value's [`ValueKind`], or `None` for [`Null`](Value::Null),
    /// [`Undefined`](Value::Undefined) and
    /// [`Passthrough`](Value::Passthrough), which no field is declared as
    /// (see the [`kind` module docs](crate::kind)).
    pub fn kind(&self) -> Option<ValueKind> {
        // Exhaustive on purpose: a new `Value` variant must decide its
        // kind here before the crate compiles.
        match self {
            Value::Bool(_) => Some(ValueKind::Bool),
            Value::Int32(_) => Some(ValueKind::Int32),
            Value::Int64(_) => Some(ValueKind::Int64),
            Value::UInt32(_) => Some(ValueKind::UInt32),
            Value::UInt64(_) => Some(ValueKind::UInt64),
            Value::Float32(_) => Some(ValueKind::Float32),
            Value::Float64(_) => Some(ValueKind::Float64),
            Value::String(_) => Some(ValueKind::String),
            Value::Bytes(_) => Some(ValueKind::Bytes),
            Value::Int8(_) => Some(ValueKind::Int8),
            Value::UInt8(_) => Some(ValueKind::UInt8),
            Value::Int16(_) => Some(ValueKind::Int16),
            Value::UInt16(_) => Some(ValueKind::UInt16),
            Value::Int128(_) => Some(ValueKind::Int128),
            Value::UInt128(_) => Some(ValueKind::UInt128),
            #[cfg(feature = "chrono")]
            Value::Date(_) => Some(ValueKind::Date),
            #[cfg(feature = "chrono")]
            Value::Timestamp(_) => Some(ValueKind::Timestamp),
            #[cfg(feature = "rust_decimal")]
            Value::Decimal(_) => Some(ValueKind::Decimal),
            Value::Array(_) => Some(ValueKind::Array),
            Value::Object(_) => Some(ValueKind::Object),
            Value::Null | Value::Undefined | Value::Passthrough(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::Protected;

    /// One value per `Value` variant, and the kind it should report.
    ///
    /// The `match` is exhaustive with no wildcard, so adding a `Value`
    /// variant fails to compile here until it is given a sample and a kind
    /// (or explicitly none).
    fn samples() -> Vec<(Value, Option<ValueKind>)> {
        let all = [
            Value::Null,
            Value::Undefined,
            Value::Bool(false),
            Value::Bool(true),
            Value::Int32(-3),
            Value::Int64(-4),
            Value::UInt32(34),
            Value::UInt64(35),
            Value::Float32(1.5),
            Value::Float64(2.5),
            Value::String("alice".into()),
            Value::Bytes(Protected::new(b"ab".to_vec())),
            Value::Int8(1),
            Value::UInt8(1),
            Value::Int16(1),
            Value::UInt16(1),
            Value::Int128(1),
            Value::UInt128(1),
            #[cfg(feature = "chrono")]
            Value::Date(chrono::NaiveDate::default()),
            #[cfg(feature = "chrono")]
            Value::Timestamp(chrono::DateTime::UNIX_EPOCH),
            #[cfg(feature = "rust_decimal")]
            Value::Decimal(rust_decimal::Decimal::ZERO),
            Value::Array(vec![Value::UInt32(1)]),
            Value::Object(vec![("k".to_string(), Value::UInt32(1))]),
            Value::Passthrough(Box::new(Value::UInt32(1))),
        ];
        all.into_iter()
            .map(|value| {
                let expected = match &value {
                    Value::Null | Value::Undefined | Value::Passthrough(_) => None,
                    Value::Bool(_) => Some(ValueKind::Bool),
                    Value::Int32(_) => Some(ValueKind::Int32),
                    Value::Int64(_) => Some(ValueKind::Int64),
                    Value::UInt32(_) => Some(ValueKind::UInt32),
                    Value::UInt64(_) => Some(ValueKind::UInt64),
                    Value::Float32(_) => Some(ValueKind::Float32),
                    Value::Float64(_) => Some(ValueKind::Float64),
                    Value::String(_) => Some(ValueKind::String),
                    Value::Bytes(_) => Some(ValueKind::Bytes),
                    Value::Int8(_) => Some(ValueKind::Int8),
                    Value::UInt8(_) => Some(ValueKind::UInt8),
                    Value::Int16(_) => Some(ValueKind::Int16),
                    Value::UInt16(_) => Some(ValueKind::UInt16),
                    Value::Int128(_) => Some(ValueKind::Int128),
                    Value::UInt128(_) => Some(ValueKind::UInt128),
                    #[cfg(feature = "chrono")]
                    Value::Date(_) => Some(ValueKind::Date),
                    #[cfg(feature = "chrono")]
                    Value::Timestamp(_) => Some(ValueKind::Timestamp),
                    #[cfg(feature = "rust_decimal")]
                    Value::Decimal(_) => Some(ValueKind::Decimal),
                    Value::Array(_) => Some(ValueKind::Array),
                    Value::Object(_) => Some(ValueKind::Object),
                };
                (value, expected)
            })
            .collect()
    }

    #[test]
    fn every_variant_reports_its_kind_and_all_covers_every_kinded_variant() {
        let mut reported = Vec::new();
        for (value, expected) in samples() {
            assert_eq!(value.kind(), expected, "{value:?}");
            if let Some(kind) = expected {
                if !reported.contains(&kind) {
                    reported.push(kind);
                }
            }
        }
        let available: Vec<_> = ValueKind::ALL
            .into_iter()
            .filter(|kind| match kind {
                ValueKind::Date | ValueKind::Timestamp => cfg!(feature = "chrono"),
                ValueKind::Decimal => cfg!(feature = "rust_decimal"),
                _ => true,
            })
            .collect();
        assert_eq!(
            reported, available,
            "ALL covers every enabled kind, in order"
        );
    }

    #[test]
    fn a_kind_holds_exactly_the_values_of_that_kind() {
        for (value, expected) in samples() {
            for kind in ValueKind::ALL {
                assert_eq!(
                    kind.holds(&value),
                    Some(kind) == expected,
                    "{kind} holds {value:?}?"
                );
            }
        }
    }

    #[test]
    fn names_are_the_frozen_wire_spelling_and_round_trip() {
        let names: Vec<_> = ValueKind::ALL.iter().map(|kind| kind.name()).collect();
        assert_eq!(
            names,
            [
                "bool",
                "int32",
                "int64",
                "uint32",
                "uint64",
                "float32",
                "float64",
                "string",
                "bytes",
                "int8",
                "uint8",
                "int16",
                "uint16",
                "int128",
                "uint128",
                "date",
                "timestamp",
                "decimal",
                "array",
                "object"
            ],
            "the names are wire format"
        );
        for kind in ValueKind::ALL {
            assert_eq!(kind.name().parse::<ValueKind>(), Ok(kind));
            assert_eq!(kind.to_string(), kind.name());
        }
        for not_a_kind in [
            "",
            "UInt64",
            "Bool",
            "u64",
            " uint64",
            "uint64 ",
            "int",
            "number",
            "null",
            "undefined",
            "passthrough",
            "text",
        ] {
            assert_eq!(
                not_a_kind.parse::<ValueKind>(),
                Err(ParseValueKindError),
                "{not_a_kind:?}"
            );
        }
        assert_eq!(ParseValueKindError.to_string(), "not a value kind");
    }

    /// The kinds are the tag table: every tag but `NULL` and `UNDEFINED`
    /// belongs to exactly one kind, and the containers to none.
    #[test]
    fn tags_partition_the_scalar_tag_table() {
        let mut claimed: Vec<u8> = ValueKind::ALL
            .iter()
            .flat_map(|kind| kind.tags().iter().copied())
            .collect();
        claimed.sort_unstable();
        let mut expected_tags = [
            tags::BOOL_FALSE,
            tags::BOOL_TRUE,
            tags::INT32,
            tags::INT64,
            tags::UINT32,
            tags::UINT64,
            tags::FLOAT32,
            tags::FLOAT64,
            tags::STRING,
            tags::BYTES,
            tags::INT8,
            tags::UINT8,
            tags::INT16,
            tags::UINT16,
            tags::INT128,
            tags::UINT128,
            tags::DATE,
            tags::TIMESTAMP,
            tags::DECIMAL,
        ];
        expected_tags.sort_unstable();
        assert_eq!(claimed, expected_tags);
        let expected: [(ValueKind, &[u8]); 20] = [
            (ValueKind::Bool, &[tags::BOOL_FALSE, tags::BOOL_TRUE]),
            (ValueKind::Int32, &[tags::INT32]),
            (ValueKind::Int64, &[tags::INT64]),
            (ValueKind::UInt32, &[tags::UINT32]),
            (ValueKind::UInt64, &[tags::UINT64]),
            (ValueKind::Float32, &[tags::FLOAT32]),
            (ValueKind::Float64, &[tags::FLOAT64]),
            (ValueKind::String, &[tags::STRING]),
            (ValueKind::Bytes, &[tags::BYTES]),
            (ValueKind::Int8, &[tags::INT8]),
            (ValueKind::UInt8, &[tags::UINT8]),
            (ValueKind::Int16, &[tags::INT16]),
            (ValueKind::UInt16, &[tags::UINT16]),
            (ValueKind::Int128, &[tags::INT128]),
            (ValueKind::UInt128, &[tags::UINT128]),
            (ValueKind::Date, &[tags::DATE]),
            (ValueKind::Timestamp, &[tags::TIMESTAMP]),
            (ValueKind::Decimal, &[tags::DECIMAL]),
            (ValueKind::Array, &[]),
            (ValueKind::Object, &[]),
        ];
        for (kind, tags) in expected {
            assert_eq!(kind.tags(), tags, "{kind}");
        }
    }
}
