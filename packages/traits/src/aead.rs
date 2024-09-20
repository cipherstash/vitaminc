use vitaminc_protected::Controlled;

pub struct Aad<A>(A) where A: AsRef<[u8]>;

pub struct Nonce<const N: usize>([u8; N]);

// TODO: How do we prevent users from using this trait directly?
// We could make the plaintext type a named type with a private contructor
pub trait AeadCore<const NONCE_SIZE: usize> {
    type Error; // TODO: Define a SAFE error type to prevent leaking sensitive information
    type NonceGen: NonceGenerator<NONCE_SIZE>;

    // Required methods
    fn encrypt_with_aad<C, A>(
        &self,
        plaintext: C,
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<Vec<u8>, Self::Error> where C: Controlled, A: AsRef<[u8]>;

    fn encrypt<C>(
        &self,
        plaintext: C,
        nonce: Nonce<NONCE_SIZE>,
    ) -> Result<Vec<u8>, Self::Error> where C: Controlled {
        self.encrypt_with_aad(plaintext, nonce, Aad(&[]))
    }

    fn decrypt_with_aad<C, A>(
        &self,
        ciphertext: Vec<u8>,
        nonce: Nonce<NONCE_SIZE>,
        aad: Aad<A>,
    ) -> Result<C, Self::Error> where C: Controlled, A: AsRef<[u8]>;

    fn decrypt<C>(
        &self,
        nonce: Nonce<NONCE_SIZE>,
        ciphertext: Vec<u8>,
    ) -> Result<C, Self::Error> where C: Controlled {
        self.decrypt_with_aad(ciphertext, nonce, Aad(&[]))
    }
}

pub trait NonceGenerator<const N: usize> {
    fn generate(&self) -> Nonce<N>;
}

pub struct Aead<const NONCE_SIZE: usize, A: AeadCore<NONCE_SIZE>>(A);

impl<const NONCE_SIZE: usize, A: AeadCore<NONCE_SIZE>> Aead<NONCE_SIZE, A> {
    pub fn new(a: A) -> Self {
        Self(a)
    }

    pub fn encrypt_with_aad<C, Aad>(
        &self,
        plaintext: C,
        aad: Aad,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), A::Error> where C: Controlled, Aad: AsRef<[u8]> {
        self.0.encrypt_with_aad(plaintext, Aad(aad))
    }

    pub fn encrypt<C>(
        &self,
        plaintext: C,
    ) -> Result<(Nonce<NONCE_SIZE>, Vec<u8>), A::Error> where C: Controlled {
        self.0.encrypt(plaintext)
    }

    pub fn decrypt_with_aad<C, Aad>(
        &self,
        nonce: Nonce<NONCE_SIZE>,
        ciphertext: Vec<u8>,
    ) -> Result<C, A::Error> where C: Controlled, Aad: AsRef<[u8]> {
        self.0.decrypt_with_aad(nonce, ciphertext)
    }

    pub fn decrypt<C>(
        &self,
        nonce: Nonce<NONCE_SIZE>,
        ciphertext: Vec<u8>,
    ) -> Result<C, A::Error> {
        self.0.decrypt(nonce, ciphertext)
    }
}
