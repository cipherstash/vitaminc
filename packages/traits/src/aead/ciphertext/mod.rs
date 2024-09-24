mod read_monads;
mod write_monads;
use bytes::Bytes;
use read_monads::CipherTextReader;
use serde::{Deserialize, Serialize};
pub use write_monads::CipherTextBuilder;

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CipherText(Bytes);

impl CipherText {
    pub fn into_inner(self) -> Bytes {
        self.0
    }

    pub fn into_reader(self) -> CipherTextReader {
        CipherTextReader::new(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Nonce;
    use vitaminc_protected::{Controlled, Protected};

    #[test]
    fn test_ciphertext_builder_with_plaintext_in_place() -> Result<(), ()> {
        let nonce = Nonce([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);
        let ciphertext = CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut ciphertext| {
                ciphertext.copy_from_slice(&[2u8; 10]);
                ciphertext.extend([3u8; 16]);
                Ok(ciphertext)
            })
            .build()?;

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);

        Ok(())
    }

    #[test]
    fn test_ciphertext_reader() -> Result<(), ()> {
        let nonce = Nonce([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);

        let ciphertext = CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut ciphertext| {
                ciphertext.copy_from_slice(&[2u8; 10]);
                ciphertext.extend([3u8; 16]);
                Ok(ciphertext)
            })
            .build()?;

        let (nonce, reader) = ciphertext.into_reader().read_nonce::<12>();

        let plaintext = reader
            .accepts_plaintext_ok(|mut data| {
                assert_eq!(data.len(), 26);
                assert_eq!(&data[..10], [2u8; 10]);
                assert_eq!(&data[10..], [3u8; 16]);
                // Write in the same way as AWS-LC/Ring does
                data[..10].copy_from_slice(&[0u8; 10]);
                Ok(data)
            })
            .read()?;

        assert_eq!(nonce.into_inner(), [1u8; 12]);
        assert_eq!(plaintext.risky_unwrap()[..10], vec![0u8; 10]);

        Ok(())
    }
    /*
    #[test]
    fn test_ciphertext_builder_with_extend() {
        let nonce = Nonce([1u8; 12]);
        let encrypted: Vec<u8> = vec![2u8; 10];
        let mut builder = CipherTextBuilder::<12, 16>::new(10)
            .append_nonce(&nonce);

        builder.extend(encrypted);
        let ciphertext = builder.append_tag(&[3u8; 16]).build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);
    }

    #[test]
    fn test_ciphertext_builder_with_ciphertext_mut() {
        let nonce = Nonce([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);
        let encrypted: Vec<u8> = vec![2u8; 10];
        let mut builder = CipherTextBuilder::<12, 16>::new(10)
            .append_nonce(&nonce)
            .append_target_plaintext(plaintext);

        let ciphertext = builder.ciphertext_mut().unwrap();
        ciphertext.copy_from_slice(&encrypted);
        let ciphertext = builder.append_tag(&[3u8; 16]).build();

        assert_eq!(ciphertext.0.len(), 38);
        assert_eq!(&ciphertext.0[..12], &[1u8; 12]);
        assert_eq!(&ciphertext.0[12..22], &[2u8; 10]);
        assert_eq!(&ciphertext.0[22..], &[3u8; 16]);
    }*/
}
