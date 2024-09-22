use aws_lc_rs::{
    aead::{LessSafeKey, UnboundKey, AES_256_GCM},
    error::Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_traits::{Aad, AeadCore, CipherText, CipherTextBuilder, KeyInit, Nonce, RandomNonceGenerator};

// TODO: Wrap the key in a Protected first
#[derive(Debug)]
pub struct AwsLcAeadCore(LessSafeKey);

impl KeyInit<32> for AwsLcAeadCore {
    type Key = Protected<[u8; 32]>;

    fn new(key: Self::Key) -> Self {
        let key_bytes = key.risky_unwrap();
        let unboundkey = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        // TODO: make sure to zeroize key_bytes - does LessSafeKey zeroize?
        Self(LessSafeKey::new(unboundkey))
    }
}

impl AeadCore<12> for AwsLcAeadCore {
    type Error = Unspecified;
    type NonceGen = RandomNonceGenerator<12>;

    fn encrypt_with_aad<A>(
        &self,
        plaintext: Protected<Vec<u8>>,
        nonce: Nonce<12>,
        aad: Aad<A>,
    ) -> Result<CipherText, Self::Error>
    where
        A: AsRef<[u8]>,
    {
        let nonce_lc = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce.as_ref())?;
        // FIXME: WE can't get len of Protected so we need to unwrap it
        let plaintext = plaintext.risky_unwrap();
        let mut builder = CipherTextBuilder::<12>::new(plaintext.len())
            .append_nonce(&nonce)
            .append_target_plaintext(Protected::new(plaintext))
            .accepts_ciphertext_and_tag();

        self.0
            .seal_in_place_append_tag(nonce_lc, aws_lc_rs::aead::Aad::from(aad), &mut builder)?;
        
        builder.try_build().map_err(|_| Unspecified)
    }

    fn decrypt_with_aad<A>(
        &self,
        ciphertext: CipherText,
        aad: Aad<A>,
    ) -> Result<Protected<Vec<u8>>, Self::Error>
    where
        A: AsRef<[u8]>,
    {
        /*let mut builder: CipherTextBuilder<12, 16> = ciphertext.into_builder();
        let nonce = builder.read_nonce();
        let nonce_lc = aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce.into_inner());
        self.0
            .open_in_place(nonce_lc, aws_lc_rs::aead::Aad::from(aad), builder.as_mut())?;
        Ok(builder.into_plaintext())*/
        unimplemented!()
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
        let mut aead: Aead<12, AwsLcAeadCore> = Aead::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt(input)?;
        let pt: Equatable<Protected<String>> = aead.decrypt(ciphertext)?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }
}
