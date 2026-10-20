//! Schemes for the tests. The real ones live in the scheme crates, which
//! depend on this crate, so this crate tests its trait through mocks: one
//! that takes every domain and keeps the plaintext order, and one of a
//! fixed width that refuses every other domain, as block ORE does.

#![allow(dead_code)]

use core::cmp::Ordering;
use core::convert::Infallible;

use vitaminc_ore::{Context, OrderKeyInit, OrderPlaintext, OrderScheme, OrderTarget};
use vitaminc_protected::{Controlled, Protected};

/// A term from a mock: the salt and key it was bound under, then the
/// plaintext bytes, which it "encrypts" by keeping. Its stored form is
/// all three, so it depends on the key and the salt as a real term must.
/// Terms under one salt and key compare as the values do; a mock refuses
/// to compare terms of different spaces, which a real scheme cannot
/// always tell apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockTerm {
    stored: Vec<u8>,
    /// Where the plaintext bytes start.
    split: usize,
}

impl MockTerm {
    fn new(salt: Vec<u8>, bytes: &[u8]) -> Self {
        let split = salt.len();
        let mut stored = salt;
        stored.extend_from_slice(bytes);
        Self { stored, split }
    }

    /// The salt and key the term was bound under.
    pub fn salt(&self) -> &[u8] {
        &self.stored[..self.split]
    }

    /// The plaintext bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.stored[self.split..]
    }
}

/// The mocks' comparison: the values' order within one space, `None`
/// across spaces.
fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
    (a.salt() == b.salt()).then(|| a.bytes().cmp(b.bytes()))
}

impl AsRef<[u8]> for MockTerm {
    fn as_ref(&self) -> &[u8] {
        &self.stored
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

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        let mut salt = salt.as_bytes().to_vec();
        salt.extend_from_slice(self.key.risky_ref());
        Ok(MockTerm::new(salt, plaintext.bytes().risky_ref()))
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_every_target!(Mock);

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
/// the shape of a block ORE scheme. A target named when the program is
/// compiled is one of the `Supports` impls below; one chosen while it
/// runs is asked its width. A plaintext of another width is a bug in the
/// space, which should have refused it, so the mock panics on one.
pub struct Fixed<const N: usize>(pub Mock);

impl<const N: usize> OrderScheme for Fixed<N> {
    const NAME: &'static str = "fixed";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        assert_eq!(plaintext.width(), Some(N), "the space let a width through");
        self.0.encrypt_plaintext(plaintext, salt)
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

// The targets of each width the tests use, both answers from one list.
vitaminc_ore::supports_targets!(Fixed<1>; I8, U8);
vitaminc_ore::supports_targets!(Fixed<2>; I16, U16);
vitaminc_ore::supports_targets!(Fixed<4>; I32, U32, Date);
vitaminc_ore::supports_targets!(Fixed<8>; I64, U64, F64);

/// A four-byte scheme whose `Supports<I64>` impl, written by hand, lies:
/// its runtime list refuses an `I64`. For the conformance check that
/// catches the disagreement, and for the space's debug assertion, which
/// fires when a space of `I64` is opened on it.
pub struct Lying(pub Fixed<4>);

impl OrderScheme for Lying {
    const NAME: &'static str = "lying";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        self.0.encrypt_plaintext(plaintext, salt)
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_targets!(Lying; I32, U32, Date);

impl vitaminc_ore::Supports<vitaminc_ore::target::I64> for Lying {
    fn supports(_: vitaminc_ore::target::I64) -> bool {
        true
    }
}

/// A scheme that forgets the salt and the key for a text term shorter
/// than two bytes: the shape of the empty-term bug the scheme crates had,
/// for the conformance checks to catch.
pub struct Unsalted(pub Mock);

impl OrderScheme for Unsalted {
    const NAME: &'static str = "unsalted";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        if plaintext.target() == OrderTarget::Text && plaintext.bytes().risky_ref().len() < 2 {
            return Ok(MockTerm::new(Vec::new(), plaintext.bytes().risky_ref()));
        }
        self.0.encrypt_plaintext(plaintext, salt)
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_every_target!(Unsalted);

/// A scheme whose term for a text shorter than two bytes is empty: the
/// stored form of a term with no blocks, for the check that no term is
/// empty to catch.
pub struct Empty(pub Mock);

impl OrderScheme for Empty {
    const NAME: &'static str = "empty";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        if plaintext.target() == OrderTarget::Text && plaintext.bytes().risky_ref().len() < 2 {
            return Ok(MockTerm::new(Vec::new(), &[]));
        }
        self.0.encrypt_plaintext(plaintext, salt)
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_every_target!(Empty);

/// A scheme that binds the salt but not the key, for the conformance
/// checks to catch a term that does not depend on the key.
pub struct Unkeyed(pub Mock);

impl OrderScheme for Unkeyed {
    const NAME: &'static str = "unkeyed";
    type Term = MockTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<MockTerm, Infallible> {
        Ok(MockTerm::new(
            salt.as_bytes().to_vec(),
            plaintext.bytes().risky_ref(),
        ))
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_every_target!(Unkeyed);

/// A term whose comparison knows the salt and key it was bound under,
/// but whose stored bytes leave out the key, and the salt too unless
/// `keeps_salt`: the shape of a scheme that keys its terms in memory and
/// drops what it keyed them with when it stores them.
pub struct ForgetfulTerm {
    bound: Vec<u8>,
    stored: Vec<u8>,
}

impl AsRef<[u8]> for ForgetfulTerm {
    fn as_ref(&self) -> &[u8] {
        &self.stored
    }
}

/// A scheme whose stored terms forget the key, and the salt too unless
/// `keeps_salt`, for the conformance checks on a term's bytes to catch.
/// Its comparison still tells the spaces apart, so the checks that go
/// through `compare` pass and only the byte checks see the bug.
pub struct Forgetful {
    pub mock: Mock,
    pub keeps_salt: bool,
}

impl OrderScheme for Forgetful {
    const NAME: &'static str = "forgetful";
    type Term = ForgetfulTerm;
    type Error = Infallible;

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
        salt: &Context<'_>,
    ) -> Result<ForgetfulTerm, Infallible> {
        let mut bound = salt.as_bytes().to_vec();
        bound.extend_from_slice(self.mock.key.risky_ref());
        let mut stored = if self.keeps_salt {
            salt.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        stored.extend_from_slice(plaintext.bytes().risky_ref());
        Ok(ForgetfulTerm { bound, stored })
    }

    fn compare(a: &ForgetfulTerm, b: &ForgetfulTerm) -> Option<Ordering> {
        (a.bound == b.bound).then(|| a.stored.cmp(&b.stored))
    }
}

vitaminc_ore::supports_every_target!(Forgetful);

/// A scheme whose backend fails.
pub struct Down;

#[derive(Debug, thiserror::Error)]
#[error("the backend is down")]
pub struct BackendDown;

impl OrderScheme for Down {
    const NAME: &'static str = "down";
    type Term = MockTerm;
    type Error = BackendDown;

    fn encrypt_plaintext(
        &self,
        _: &OrderPlaintext,
        _: &Context<'_>,
    ) -> Result<MockTerm, BackendDown> {
        Err(BackendDown)
    }

    fn compare(a: &MockTerm, b: &MockTerm) -> Option<Ordering> {
        compare(a, b)
    }
}

vitaminc_ore::supports_every_target!(Down);

pub fn key() -> Protected<[u8; 32]> {
    Protected::new([7; 32])
}
