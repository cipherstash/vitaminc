use rmp_serde::{decode, encode, Deserializer, Serializer};
use std::fmt::Debug;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected, SafeDeserialize, SafeSerialize};
use vitaminc_random::{Generatable, SafeRand, SeedableRng};
use zeroize::Zeroize;

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

pub trait KeyInit<const KEY_SIZE: usize> {
    type Key: Controlled<Inner = [u8; KEY_SIZE]>;

    fn new(key: Self::Key) -> Self;
}

// TODO: How do we prevent users from using this trait directly?
// We could make the plaintext type a named type with a private contructor
pub trait AeadCore<const NONCE_SIZE: usize> {
    type Error: std::error::Error; // TODO: Define a SAFE error type to prevent leaking sensitive information
    type NonceGen: NonceGenerator<NONCE_SIZE>;

    // Required methods
    fn encrypt_with_aad<A>(
        &self,
        plaintext: Protected<Vec<u8>>,
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), Self::Error>
    where
        A: AsRef<[u8]>;

    fn encrypt(
        &self,
        plaintext: Protected<Vec<u8>>,
        nonce: Nonce<NONCE_SIZE>,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), Self::Error> {
        self.encrypt_with_aad(plaintext, nonce, Aad(&[]))
    }

    fn decrypt_with_aad<A>(
        &self,
        ciphertext: Vec<u8>,
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<Protected<Vec<u8>>, Self::Error>
    where
        A: AsRef<[u8]>;

    fn decrypt(
        &self,
        nonce: Nonce<NONCE_SIZE>,
        ciphertext: Vec<u8>,
    ) -> Result<Protected<Vec<u8>>, Self::Error> {
        self.decrypt_with_aad(ciphertext, nonce, Aad(&[]))
    }
}

pub struct Aead<const NONCE_SIZE: usize, A: AeadCore<NONCE_SIZE>>(A, A::NonceGen);

#[derive(Debug, Error)]
pub enum AeadError<const NONCE_SIZE: usize, C: AeadCore<NONCE_SIZE>> {
    #[error(transparent)]
    CoreError(C::Error),
    #[error("Encoding failed")]
    Encode(#[from] encode::Error),
    #[error("Decoding failed")]
    Decode(#[from] decode::Error),
}

impl<const NONCE_SIZE: usize, CIPHER: AeadCore<NONCE_SIZE>> Aead<NONCE_SIZE, CIPHER> {
    pub fn new(a: CIPHER) -> Self {
        Self(a, CIPHER::NonceGen::init())
    }

    pub fn encrypt_with_aad<C, A>(
        &mut self,
        plaintext: C,
        aad: Aad<A>,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), AeadError<NONCE_SIZE, CIPHER>>
    where
        C: Controlled + SafeSerialize,
        A: AsRef<[u8]>,
    {
        let nonce = self.1.generate();
        let input = safe_serialize(plaintext);
        self.0
            .encrypt_with_aad(input, nonce, aad)
            .map_err(AeadError::CoreError)
    }

    pub fn encrypt<C>(
        &mut self,
        plaintext: C,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), AeadError<NONCE_SIZE, CIPHER>>
    where
        C: Controlled + SafeSerialize,
    {
        self.encrypt_with_aad(plaintext, Aad(&[]))
    }

    // TODO: Can we tidy these up a a bit!?
    pub fn decrypt_with_aad<T, A>(
        &self,
        ciphertext: Vec<u8>,
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<T, AeadError<NONCE_SIZE, CIPHER>>
    where
        T: for<'de> SafeDeserialize<'de>,
        A: AsRef<[u8]>,
    {
        let result = self
            .0
            .decrypt_with_aad(ciphertext, nonce, aad)
            .map_err(AeadError::CoreError)?;
        Ok(safe_deserialize(result)?)
    }

    pub fn decrypt<T>(
        &self,
        ciphertext: Vec<u8>,
        nonce: Nonce<NONCE_SIZE>,
    ) -> Result<T, AeadError<NONCE_SIZE, CIPHER>>
    where
        T: for<'de> SafeDeserialize<'de>,
    {
        self.decrypt_with_aad(ciphertext, nonce, Aad(&[]))
    }
}

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
    T: SafeSerialize,
{
    // Wrapping in a protected immediately means that the input is zeroized even if the serialization fails
    Protected::new(Vec::new()).map(|mut wr| {
        let mut serializer = Serializer::new(&mut wr);
        // FIXME: map_ok would avoid the unwrap here
        input.safe_serialize(&mut serializer).map(|_| wr).unwrap()
    })
}

#[inline]
fn safe_deserialize<T>(input: Protected<Vec<u8>>) -> Result<T, rmp_serde::decode::Error>
where
    T: for<'de> SafeDeserialize<'de>,
{
    // FIXME: If SafeDeserializer could take a Protected<Vec<u8>> we could avoid the risky_unwrap here
    let mut input = input.risky_unwrap();
    let mut deserializer = Deserializer::new(input.as_slice());
    let result = T::safe_deserialize(&mut deserializer);
    input.zeroize();
    result
}
