//! Value kinds — the FFI type vocabulary, without a value.
//!
//! A binding for a dynamically typed host (JavaScript, PHP, Ruby) often has
//! to say what a field's values *are* before it has one: "this field holds
//! `uint64`s", not "here is a `34`". [`ValueKind`] is that declaration. It is
//! the [`FfiValue`] model with the payload taken away: one kind per scalar
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
//! So [`FfiValue::kind`] is `None` for those three variants, and no kind
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
//! use vitaminc_aead_value::{FfiValue, ValueKind};
//!
//! let kind: ValueKind = "uint64".parse().unwrap();
//! assert_eq!(kind, ValueKind::UInt64);
//! assert!(kind.holds(&FfiValue::UInt64(34)));
//! assert!(!kind.holds(&FfiValue::Float64(34.0)));
//! assert_eq!(FfiValue::UInt64(34).kind(), Some(ValueKind::UInt64));
//! assert_eq!(FfiValue::Null.kind(), None);
//! ```

use std::fmt;
use std::str::FromStr;

use crate::{tags, FfiValue};

/// The kind of an [`FfiValue`]: its variant, without a payload.
///
/// This is the type vocabulary a binding declares a field with. See the
/// [module docs](self) for why `Null`, `Undefined` and `Passthrough` have no
/// kind, and why [`name`](Self::name) is frozen.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ValueKind {
    /// `"bool"`: [`FfiValue::Bool`], tags [`BOOL_FALSE`](tags::BOOL_FALSE)
    /// and [`BOOL_TRUE`](tags::BOOL_TRUE).
    Bool,
    /// `"int32"`: [`FfiValue::Int32`], tag [`INT32`](tags::INT32).
    Int32,
    /// `"int64"`: [`FfiValue::Int64`], tag [`INT64`](tags::INT64).
    Int64,
    /// `"uint32"`: [`FfiValue::UInt32`], tag [`UINT32`](tags::UINT32).
    UInt32,
    /// `"uint64"`: [`FfiValue::UInt64`], tag [`UINT64`](tags::UINT64).
    UInt64,
    /// `"float32"`: [`FfiValue::Float32`], tag [`FLOAT32`](tags::FLOAT32).
    Float32,
    /// `"float64"`: [`FfiValue::Float64`], tag [`FLOAT64`](tags::FLOAT64).
    Float64,
    /// `"string"`: [`FfiValue::String`], tag [`STRING`](tags::STRING).
    String,
    /// `"bytes"`: [`FfiValue::Bytes`], tag [`BYTES`](tags::BYTES).
    Bytes,
    /// `"array"`: [`FfiValue::Array`], sealed in the cipher's sequence mode
    /// with no tag of its own. Says nothing about the elements' kinds.
    Array,
    /// `"object"`: [`FfiValue::Object`], sealed in the cipher's map mode
    /// with no tag of its own. Says nothing about the entries' kinds.
    Object,
}

impl ValueKind {
    /// Every kind, in declaration order.
    pub const ALL: [ValueKind; 11] = [
        ValueKind::Bool,
        ValueKind::Int32,
        ValueKind::Int64,
        ValueKind::UInt32,
        ValueKind::UInt64,
        ValueKind::Float32,
        ValueKind::Float64,
        ValueKind::String,
        ValueKind::Bytes,
        ValueKind::Array,
        ValueKind::Object,
    ];

    /// How a declaration spells this kind: `"bool"`, `"int32"`, `"int64"`,
    /// `"uint32"`, `"uint64"`, `"float32"`, `"float64"`, `"string"`,
    /// `"bytes"`, `"array"` or `"object"`. Frozen wire format.
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
            ValueKind::Array | ValueKind::Object => &[],
        }
    }

    /// Whether `value` is of this kind. Exact: an `Int64` is not held by
    /// [`UInt64`](Self::UInt64), and a [`FfiValue::Passthrough`] is held by
    /// no kind, whatever it wraps.
    pub fn holds(self, value: &FfiValue) -> bool {
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

impl FfiValue {
    /// This value's [`ValueKind`], or `None` for [`Null`](FfiValue::Null),
    /// [`Undefined`](FfiValue::Undefined) and
    /// [`Passthrough`](FfiValue::Passthrough), which no field is declared as
    /// (see the [`kind` module docs](crate::kind)).
    pub fn kind(&self) -> Option<ValueKind> {
        // Exhaustive on purpose: a new `FfiValue` variant must decide its
        // kind here before the crate compiles.
        match self {
            FfiValue::Bool(_) => Some(ValueKind::Bool),
            FfiValue::Int32(_) => Some(ValueKind::Int32),
            FfiValue::Int64(_) => Some(ValueKind::Int64),
            FfiValue::UInt32(_) => Some(ValueKind::UInt32),
            FfiValue::UInt64(_) => Some(ValueKind::UInt64),
            FfiValue::Float32(_) => Some(ValueKind::Float32),
            FfiValue::Float64(_) => Some(ValueKind::Float64),
            FfiValue::String(_) => Some(ValueKind::String),
            FfiValue::Bytes(_) => Some(ValueKind::Bytes),
            FfiValue::Array(_) => Some(ValueKind::Array),
            FfiValue::Object(_) => Some(ValueKind::Object),
            FfiValue::Null | FfiValue::Undefined | FfiValue::Passthrough(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::Protected;

    /// One value per `FfiValue` variant, and the kind it should report.
    ///
    /// The `match` is exhaustive with no wildcard, so adding an `FfiValue`
    /// variant fails to compile here until it is given a sample and a kind
    /// (or explicitly none).
    fn samples() -> Vec<(FfiValue, Option<ValueKind>)> {
        let all = [
            FfiValue::Null,
            FfiValue::Undefined,
            FfiValue::Bool(false),
            FfiValue::Bool(true),
            FfiValue::Int32(-3),
            FfiValue::Int64(-4),
            FfiValue::UInt32(34),
            FfiValue::UInt64(35),
            FfiValue::Float32(1.5),
            FfiValue::Float64(2.5),
            FfiValue::String("alice".into()),
            FfiValue::Bytes(Protected::new(b"ab".to_vec())),
            FfiValue::Array(vec![FfiValue::UInt32(1)]),
            FfiValue::Object(vec![("k".to_string(), FfiValue::UInt32(1))]),
            FfiValue::Passthrough(Box::new(FfiValue::UInt32(1))),
        ];
        all.into_iter()
            .map(|value| {
                let expected = match &value {
                    FfiValue::Null | FfiValue::Undefined | FfiValue::Passthrough(_) => None,
                    FfiValue::Bool(_) => Some(ValueKind::Bool),
                    FfiValue::Int32(_) => Some(ValueKind::Int32),
                    FfiValue::Int64(_) => Some(ValueKind::Int64),
                    FfiValue::UInt32(_) => Some(ValueKind::UInt32),
                    FfiValue::UInt64(_) => Some(ValueKind::UInt64),
                    FfiValue::Float32(_) => Some(ValueKind::Float32),
                    FfiValue::Float64(_) => Some(ValueKind::Float64),
                    FfiValue::String(_) => Some(ValueKind::String),
                    FfiValue::Bytes(_) => Some(ValueKind::Bytes),
                    FfiValue::Array(_) => Some(ValueKind::Array),
                    FfiValue::Object(_) => Some(ValueKind::Object),
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
        assert_eq!(reported, ValueKind::ALL, "ALL is every kind, in order");
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
                "bool", "int32", "int64", "uint32", "uint64", "float32", "float64", "string",
                "bytes", "array", "object"
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
        assert_eq!(
            claimed,
            [
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
            ]
        );
        let expected: [(ValueKind, &[u8]); 11] = [
            (ValueKind::Bool, &[tags::BOOL_FALSE, tags::BOOL_TRUE]),
            (ValueKind::Int32, &[tags::INT32]),
            (ValueKind::Int64, &[tags::INT64]),
            (ValueKind::UInt32, &[tags::UINT32]),
            (ValueKind::UInt64, &[tags::UINT64]),
            (ValueKind::Float32, &[tags::FLOAT32]),
            (ValueKind::Float64, &[tags::FLOAT64]),
            (ValueKind::String, &[tags::STRING]),
            (ValueKind::Bytes, &[tags::BYTES]),
            (ValueKind::Array, &[]),
            (ValueKind::Object, &[]),
        ];
        for (kind, tags) in expected {
            assert_eq!(kind.tags(), tags, "{kind}");
        }
    }
}
