use thiserror::Error;

/// Errors detected while a structured PRF program is being built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrfBuildError {
    /// A value arrived before its key.
    #[error("a map value was supplied without a preceding key")]
    ValueWithoutKey,
    /// A second key arrived while the preceding key still needed a value.
    #[error("a map key was supplied before the preceding key received a value")]
    KeyWithoutValue,
    /// The map was finished with an unpaired key.
    #[error("a map ended while a key was still waiting for a value")]
    DanglingKey,
    /// An entry reused a key already present in the map.
    #[error("a map key was supplied more than once")]
    DuplicateKey,
    /// A boxed passthrough value could not be represented by this backend.
    #[error("the backend rejected a boxed passthrough value")]
    InvalidPassthrough,
}

/// Errors produced when a visitor is used with the wrong resolved shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrfVisitorError {
    /// The visitor does not accept this node kind.
    #[error("the PRF result had an unexpected structural shape")]
    UnexpectedShape,
    /// The node kind is accepted, but its contents cannot produce the requested value.
    #[error("the PRF result could not be converted to the requested value")]
    InvalidValue,
}

/// A structured PRF failure.
///
/// Builder and visitor failures describe malformed local structure. Backend
/// failures describe execution of an otherwise valid program (for example, a
/// remote batch request being rejected).
///
/// Non-exhaustive: optional features add variants.
#[derive(Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PrfError<E> {
    /// A scalar with no equality term, or one that could not be normalized
    /// (requires the `normalize` feature).
    #[cfg(feature = "normalize")]
    #[error("cannot derive an equality term: {0}")]
    Normalize(#[from] vitaminc_normalize::NormalizeError),
    /// Invalid driver call order, duplicate key, or unsupported passthrough.
    #[error("failed to build PRF operation: {0}")]
    Build(#[from] PrfBuildError),
    /// The final visitor or a child visitor refused the resolved result.
    #[error("failed to interpret PRF result: {0}")]
    Visitor(#[from] PrfVisitorError),
    /// Execution failed in the cryptographic or remote backend.
    #[error("PRF backend failed: {0}")]
    Backend(E),
}
