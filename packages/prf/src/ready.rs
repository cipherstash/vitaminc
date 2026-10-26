use std::future::{ready, IntoFuture, Ready};

use crate::PrfError;

/// An immediately available, awaitable PRF result.
#[must_use = "PRF output does nothing until it is awaited or inspected"]
pub struct ReadyPrf<T, E> {
    result: Result<T, PrfError<E>>,
}

impl<T, E> ReadyPrf<T, E> {
    /// Wrap an already computed success or failure; this performs no derivation.
    pub fn new(result: Result<T, PrfError<E>>) -> Self {
        Self { result }
    }

    /// Consume the wrapper and obtain its result without an executor.
    /// Returns the stored error unchanged if derivation or visiting failed.
    pub fn into_result(self) -> Result<T, PrfError<E>> {
        self.result
    }
}

impl<T, E> IntoFuture for ReadyPrf<T, E> {
    type Output = Result<T, PrfError<E>>;
    type IntoFuture = Ready<Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        ready(self.result)
    }
}
