mod ciphertext;
use rmp_serde::{decode, encode, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};
use zeroize::Zeroize;

pub use ciphertext::{CipherText, CipherTextBuilder};

pub struct Aad<A>(A)
where
    A: AsRef<[u8]>;

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct Nonce<const N: usize>([u8; N]);

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Nonce<N> {
    fn new(inner: [u8; N]) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> [u8; N] {
        self.0
    }
}

pub trait KeyInit<const KEY_SIZE: usize> {
    type Key: Controlled<Inner = [u8; KEY_SIZE]>;

    fn new(key: Self::Key) -> Self;
}

// TODO: How do we prevent users from using this trait directly?
// We could make the plaintext type a named type with a private contructor
// FIXME: Making this generic on NonceSize is a bit awkward
pub trait AeadCore<const NONCE_SIZE: usize> {
    type Error: std::error::Error + Send + Sync; // TODO: Define a SAFE error type to prevent leaking sensitive information
    type NonceGen: NonceGenerator<NONCE_SIZE>;

    // Required methods
    fn encrypt_with_aad<A>(
        &self,
        plaintext: Protected<Vec<u8>>,
        // TODO: Instead of taking the Nonce, we could take a builder
        // which either _has_ a nonce generated already or allows us to call generate (possibly with an arg) and then build
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<CipherText, Self::Error>
    where
        A: AsRef<[u8]>;

    fn encrypt(
        &self,
        plaintext: Protected<Vec<u8>>,
        nonce: Nonce<NONCE_SIZE>,
    ) -> Result<CipherText, Self::Error> {
        self.encrypt_with_aad(plaintext, nonce, Aad(&[]))
    }

    fn decrypt_with_aad<A>(
        &self,
        ciphertext: CipherText,
        aad: Aad<A>,
    ) -> Result<Protected<Vec<u8>>, Self::Error>
    where
        A: AsRef<[u8]>;

    fn decrypt(&self, ciphertext: CipherText) -> Result<Protected<Vec<u8>>, Self::Error> {
        self.decrypt_with_aad(ciphertext, Aad(&[]))
    }
}

pub struct Aead<const NONCE_SIZE: usize, A: AeadCore<NONCE_SIZE>>(A, A::NonceGen);

#[derive(Debug, Error)]
pub enum AeadError {
    #[error(transparent)]
    CoreError(anyhow::Error),
    #[error("Encoding failed")]
    Encode(#[from] encode::Error),
    #[error("Decoding failed")]
    Decode(#[from] decode::Error),
}

impl AeadError {
    pub fn from_core_error<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::CoreError(anyhow::Error::new(error))
    }
}

impl<const NONCE_SIZE: usize, CIPHER: AeadCore<NONCE_SIZE>> Aead<NONCE_SIZE, CIPHER> {
    pub fn new<const N: usize>(key: <CIPHER as KeyInit<N>>::Key) -> Self
    where
        CIPHER: KeyInit<N>,
    {
        Self(CIPHER::new(key), CIPHER::NonceGen::init())
    }

    pub fn encrypt_with_aad<C, A>(
        &mut self,
        plaintext: C,
        aad: Aad<A>,
    ) -> Result<CipherText, AeadError>
    where
        C: Serialize,
        A: AsRef<[u8]>,
        <CIPHER as AeadCore<NONCE_SIZE>>::Error: 'static,
    {
        let nonce = self.1.generate();
        let input = safe_serialize(plaintext);
        self.0
            .encrypt_with_aad(input, nonce, aad)
            .map_err(AeadError::from_core_error)
    }

    pub fn encrypt<C>(&mut self, plaintext: C) -> Result<CipherText, AeadError>
    where
        C: Serialize,
        <CIPHER as AeadCore<NONCE_SIZE>>::Error: 'static,
    {
        self.encrypt_with_aad(plaintext, Aad(&[]))
    }

    pub fn decrypt_with_aad<T, A>(
        &self,
        ciphertext: CipherText,
        aad: Aad<A>,
    ) -> Result<T, AeadError>
    where
        T: for<'de> Deserialize<'de>,
        A: AsRef<[u8]>,
        <CIPHER as AeadCore<NONCE_SIZE>>::Error: 'static,
    {
        self.0
            .decrypt_with_aad(ciphertext, aad)
            .map_err(AeadError::from_core_error)
            .and_then(safe_deserialize)
    }

    pub fn decrypt<T>(&self, ciphertext: CipherText) -> Result<T, AeadError>
    where
        T: for<'de> Deserialize<'de>,
        <CIPHER as AeadCore<NONCE_SIZE>>::Error: 'static,
    {
        self.decrypt_with_aad(ciphertext, Aad(&[]))
    }
}

// TODO: Make this a trait that can be implemented for a cipher rather than an associated type on the Cipher
// That way we can have multiple implementations of the same cipher with different nonce generation strategies
pub trait NonceGenerator<const N: usize> {
    // TODO: Allow an argument to be passed to the init method or make it a separate trait entirely
    fn init() -> Self;
    fn generate(&mut self) -> Nonce<N>;
}

pub struct RandomNonceGenerator<const N: usize>(SafeRand);

impl<const N: usize> NonceGenerator<N> for RandomNonceGenerator<N> {
    fn init() -> Self {
        Self(SafeRand::from_entropy())
    }

    fn generate(&mut self) -> Nonce<N> {
        // FIXME: Should we panic if the nonce generation fails?
        Nonce(Generatable::random(&mut self.0).unwrap())
    }
}

#[inline]
fn safe_serialize<T>(input: T) -> Protected<Vec<u8>>
where
    T: Serialize,
{
    // Wrapping in a protected immediately means that the input is zeroized even if the serialization fails
    Protected::new(Vec::new()).map(|mut wr| {
        let mut serializer = Serializer::new(&mut wr);
        // FIXME: map_ok would avoid the unwrap here
        input.serialize(&mut serializer).map(|_| wr).unwrap()
    })
}

#[inline]
fn safe_deserialize<T>(input: Protected<Vec<u8>>) -> Result<T, AeadError>
where
    T: for<'de> Deserialize<'de>,
{
    // FIXME: If a SafeDeserializer could take a Protected<Vec<u8>> we could avoid the risky_unwrap here
    let mut input = input.risky_unwrap();
    let mut deserializer = Deserializer::new(input.as_slice());
    let result = T::deserialize(&mut deserializer);
    input.zeroize();
    result.map_err(AeadError::from)
}
