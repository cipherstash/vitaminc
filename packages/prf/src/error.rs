use thiserror::Error;

/// Errors detected while a structured PRF program is being built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PrfBuildError {
    #[error("a map value was supplied without a preceding key")]
    ValueWithoutKey,
    #[error("a map key was supplied before the preceding key received a value")]
    KeyWithoutValue,
    #[error("a map ended while a key was still waiting for a value")]
    DanglingKey,
    #[error("the backend rejected a boxed passthrough value")]
    InvalidPassthrough,
}

/// Errors produced when a visitor is used with the wrong resolved shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrfVisitorError {
    #[error("the PRF result had an unexpected structural shape")]
    UnexpectedShape,
    #[error("the PRF result could not be converted to the requested value")]
    InvalidValue,
}

/// A structured PRF failure.
///
/// Builder and visitor failures describe malformed local structure. Backend
/// failures describe execution of an otherwise valid program (for example, a
/// remote batch request being rejected).
#[derive(Debug, Error)]
pub enum PrfError<E> {
    #[error("failed to build PRF operation: {0}")]
    Build(#[from] PrfBuildError),
    #[error("failed to interpret PRF result: {0}")]
    Visitor(#[from] PrfVisitorError),
    #[error("PRF backend failed: {0}")]
    Backend(E),
}

impl<E: PartialEq> PartialEq for PrfError<E> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Build(a), Self::Build(b)) => a == b,
            (Self::Visitor(a), Self::Visitor(b)) => a == b,
            (Self::Backend(a), Self::Backend(b)) => a == b,
            _ => false,
        }
    }
}

impl<E: Eq> Eq for PrfError<E> {}
