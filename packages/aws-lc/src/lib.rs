use std::marker::PhantomData;

use aws_lc_rs::{
    aead::{LessSafeKey, UnboundKey, AES_256_GCM},
    error::Unspecified,
};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_traits::{
    Aad, AeadCore, CipherText, CipherTextBuilder, KeyInit, Nonce, RandomNonceGenerator,
};

// TODO: Wrap the UsafeKey in a Protected
#[derive(Debug)]
pub struct AwsLcAeadCore<KEY = Protected<[u8; 32]>>(LessSafeKey, PhantomData<KEY>);

impl<KEY> KeyInit<32> for AwsLcAeadCore<KEY> where KEY: Controlled<Inner = [u8; 32]> {
    type Key = KEY;

    fn new(key: Self::Key) -> Self {
        let key_bytes = key.risky_unwrap();
        let unboundkey = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        // TODO: make sure to zeroize key_bytes - does LessSafeKey zeroize?
        Self(LessSafeKey::new(unboundkey), PhantomData)
    }
}

impl<KEY> AeadCore<12> for AwsLcAeadCore<KEY> {
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

        CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut buf| {
                self.0
                    .seal_in_place_append_tag(nonce_lc, aws_lc_rs::aead::Aad::from(aad), &mut buf)
                    .map(|_| buf)
            })
            .build()
    }

    fn decrypt_with_aad<A>(
        &self,
        ciphertext: CipherText,
        aad: Aad<A>,
    ) -> Result<Protected<Vec<u8>>, Self::Error>
    where
        A: AsRef<[u8]>,
    {
        let (nonce, reader) = ciphertext.into_reader().read_nonce::<12>();
        let nonce_lc = aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce.into_inner());

        reader
            .accepts_plaintext_ok(|mut data| {
                self.0
                    .open_in_place(nonce_lc, aws_lc_rs::aead::Aad::from(aad), &mut data)?;
                Ok(data)
            })
            .read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::{Equatable, Exportable, Protected};
    use vitaminc_traits::Aead;

    #[test]
    fn test_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead: Aead<12, AwsLcAeadCore> = Aead::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt(input)?;
        let pt: Exportable<Equatable<Protected<String>>> = aead.decrypt(ciphertext)?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }

    #[test]
    fn test_round_trip_with_correct_aad() -> Result<(), Box<dyn std::error::Error>> {
        let aad = "public-AAD";
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead: Aead<12, AwsLcAeadCore> = Aead::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt_with_aad(input, Aad::from(aad))?;
        let pt: Exportable<Equatable<Protected<String>>> = aead.decrypt_with_aad(ciphertext, Aad::from(aad))?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }

    #[test]
    fn test_round_trip_with_wrong_aad() -> Result<(), Box<dyn std::error::Error>> {
        let aad = "public-AAD";
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead: Aead<12, AwsLcAeadCore> = Aead::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt_with_aad(input, Aad::from(aad))?;
        let pt: Result<Exportable<Equatable<Protected<String>>>, _> = aead.decrypt_with_aad(ciphertext, Aad::from("WRONG"));

        assert!(matches!(pt, Err(_)));

        Ok(())
    }

    #[test]
    fn test_round_trip_with_missing_aad() -> Result<(), Box<dyn std::error::Error>> {
        let aad = "public-AAD";
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead: Aead<12, AwsLcAeadCore> = Aead::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt_with_aad(input, Aad::from(aad))?;
        let pt: Result<Exportable<Equatable<Protected<String>>>, _> = aead.decrypt(ciphertext);

        assert!(matches!(pt, Err(_)));

        Ok(())
    }

    #[test]
    fn test_round_trip_aead_struct() -> Result<(), Box<dyn std::error::Error>> {
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead = Aead::<12, AwsLcAeadCore>::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt(input)?;
        let pt: Exportable<Equatable<Protected<String>>> = aead.decrypt(ciphertext)?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }

    #[test]
    fn test_round_trip_aead_struct_with_correct_aad() -> Result<(), Box<dyn std::error::Error>> {
        let aad = "public-AAD";
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead = Aead::<12, AwsLcAeadCore>::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt_with_aad(input, Aad::from(aad))?;
        let pt: Exportable<Equatable<Protected<String>>> = aead.decrypt_with_aad(ciphertext, Aad::from(aad))?;

        assert_eq!(pt, Equatable::<Protected<String>>::new("Hello".to_string()));

        Ok(())
    }

    #[test]
    fn test_round_trip_aead_struct_with_wrong_aad() -> Result<(), Box<dyn std::error::Error>> {
        let aad = "public-AAD";
        let input: Exportable<Protected<String>> = Exportable::new("Hello".to_string());
        let mut aead = Aead::<12, AwsLcAeadCore>::new(Protected::new([0u8; 32]));
        let ciphertext = aead.encrypt_with_aad(input, Aad::from(aad))?;
        let pt: Result<Exportable<Equatable<Protected<String>>>, _> = aead.decrypt_with_aad(ciphertext, Aad::from("NOPE"));

        assert!(matches!(pt, Err(_)));

        Ok(())
    }
}

// TODO: Add tests using the top-level Aead struct, too
// TODO: Can we use the test vectors from aws-lc?
