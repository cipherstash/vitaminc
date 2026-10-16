//! Schemes for the tests. The real ones live in the scheme crates, which
//! depend on this crate, so this crate tests its trait through mocks: one
//! that takes every domain and keeps the plaintext order, and one of a
//! fixed width that refuses every other domain, as block ORE does.

#![allow(dead_code)]

use core::convert::Infallible;

use vitaminc_ore::{Context, OrderError, OrderKeyInit, OrderPlaintext, OrderScheme};
use vitaminc_protected::{Controlled, Protected};

/// A term from a mock: the salt it was bound under and the plaintext
/// bytes, which it "encrypts" by keeping. Orders by salt then bytes, so
/// terms under one salt order as the values do and terms under different
/// salts never compare equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MockTerm {
    pub salt: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl AsRef<[u8]> for MockTerm {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Takes every domain.
pub struct Mock {
    key: Protected<[u8; 32]>,
}

impl OrderScheme for Mock {
    const NAME: &'static str = "mock";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<MockTerm, OrderError<Infallible>> {
        let mut salt = self.salt(plaintext, context).as_bytes().to_vec();
        salt.extend_from_slice(self.key.risky_ref());
        Ok(MockTerm {
            salt,
            bytes: plaintext.bytes().risky_ref().clone(),
        })
    }
}

/// Why a mock refused key material.
#[derive(Debug, thiserror::Error)]
#[error("a mock key is thirty-two bytes, not {0}")]
pub struct WrongKeyLength(pub usize);

impl OrderKeyInit for Mock {
    type Key = Protected<[u8; 32]>;
    type KeyError = WrongKeyLength;

    fn new(key: Self::Key) -> Self {
        Self { key }
    }

    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, WrongKeyLength> {
        let bytes: [u8; 32] = key
            .risky_ref()
            .as_slice()
            .try_into()
            .map_err(|_| WrongKeyLength(key.risky_ref().len()))?;
        Ok(Self::new(Protected::new(bytes)))
    }
}

/// Takes only domains of exactly `N` bytes, refusing the rest by name:
/// the shape of a block ORE scheme.
pub struct Fixed<const N: usize>(pub Mock);

impl<const N: usize> OrderScheme for Fixed<N> {
    const NAME: &'static str = "fixed";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt(
        &self,
        plaintext: &OrderPlaintext,
        context: &Context<'_>,
    ) -> Result<MockTerm, OrderError<Infallible>> {
        if plaintext.width() != Some(N) {
            return Err(OrderError::unsupported::<Self>(plaintext));
        }
        let mut term = self.0.encrypt(plaintext, context)?;
        term.salt = self.salt(plaintext, context).as_bytes().to_vec();
        Ok(term)
    }
}

/// A scheme whose backend fails.
pub struct Down;

#[derive(Debug, thiserror::Error)]
#[error("the backend is down")]
pub struct BackendDown;

impl OrderScheme for Down {
    const NAME: &'static str = "down";
    type Term = MockTerm;
    type Error = BackendDown;

    fn encrypt(
        &self,
        _: &OrderPlaintext,
        _: &Context<'_>,
    ) -> Result<MockTerm, OrderError<BackendDown>> {
        Err(OrderError::Backend(BackendDown))
    }
}

pub fn key() -> Protected<[u8; 32]> {
    Protected::new([7; 32])
}
