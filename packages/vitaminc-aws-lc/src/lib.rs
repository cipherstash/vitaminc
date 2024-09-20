use aws_lc_rs::{
    aead::{LessSafeKey, UnboundKey, AES_256_GCM},
    error::Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_traits::{Aad, AeadCore, KeyInit, Nonce, RandomNonceGenerator};

// TODO: Wrap the key in a Protected first
#[derive(Debug)]
pub struct AwsLcAeadCore<const N: usize>(LessSafeKey);

impl KeyInit<32> for AwsLcAeadCore<32> {
    type Key = Protected<[u8; 32]>;

    fn new(key: Self::Key) -> Self {
        let key_bytes = key.risky_unwrap();
        let unboundkey = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        // TODO: make sure to zeroize key_bytes - does LessSafeKey zeroize?
        Self(LessSafeKey::new(unboundkey))
    }
}

impl AeadCore<12> for AwsLcAeadCore<32> {
    type Error = Unspecified;
    type NonceGen = RandomNonceGenerator<12>;

    fn encrypt_with_aad<A>(
        &self,
        plaintext: Protected<Vec<u8>>,
        nonce: Nonce<12>,
        aad: Aad<A>,
    ) -> Result<(Nonce<12>, Vec<u8>), Self::Error>
    where
        A: AsRef<[u8]>,
    {
        let nonce_lc = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce.as_ref())?;
        let mut in_out: Vec<u8> = plaintext.risky_unwrap().into();
        self.0
            .seal_in_place_append_tag(nonce_lc, aws_lc_rs::aead::Aad::from(aad), &mut in_out)?;
        Ok((nonce, in_out))
    }

    fn decrypt_with_aad<A>(
        &self,
        ciphertext: Vec<u8>,
        nonce: Nonce<12>,
        aad: Aad<A>,
    ) -> Result<Protected<Vec<u8>>, Self::Error>
    where
        A: AsRef<[u8]>,
    {
        let nonce_lc = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce.as_ref())?;
        // TODO: Wrap ciphertext in a Protected first (requires map_ok)
        let mut in_out = ciphertext;
        self.0
            .open_in_place(nonce_lc, aws_lc_rs::aead::Aad::from(aad), &mut in_out)?;
        Ok(Protected::new(in_out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::{Equatable, Protected};
    use vitaminc_traits::Aead;

    #[test]
    fn test_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let input = Protected::new("Hello".to_string());
        let mut aead = Aead::new(AwsLcAeadCore::<32>::new(Protected::new([0u8; 32])));
        let (nonce, ct) = aead.encrypt(input)?;
        let pt: Equatable<Protected<String>> = aead.decrypt(ct, nonce)?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }
}
