use super::integrity::{self, CallError};
use crate::crypt::{DecryptWithKey, EncryptWithKey};
use crate::data_key::{
    dedup_retrieve, fan_out_generate, BatchGenerateDataKey, BatchRetrieveDataKey, Binding,
    BindingSupport, GenerateDataKey, GeneratedDataKey, KeyIsolation, KeyReconstruction,
    RetrieveDataKey,
};
use crate::key_id::KeyId;
use google_cloud_kms_v1::client::KeyManagementService;
use thiserror::Error;
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, SafeRand};

/// Errors from [`GcpDataKeySource`].
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Gcp(#[from] google_cloud_kms_v1::Error),
    /// Two consecutive responses failed the same CRC32C check: the
    /// first was discarded and retried, and the retry failed the same way.
    #[error("Google Cloud KMS responses failed their {0} integrity check twice")]
    Integrity(&'static str),
    /// The local CSPRNG could not produce key material, so nothing was
    /// sent to Google Cloud KMS.
    #[error("could not generate data key material: {0}")]
    Random(#[from] vitaminc_random::RandomError),
    /// Decrypting a `KeyId` gave back key material of the wrong length —
    /// the `KeyId` belongs to something other than an `N`-byte data key.
    /// Guards the `Vec<u8>` -> `[u8; N]` conversion so it is an error
    /// rather than a panic.
    #[error("Google Cloud KMS returned {received} bytes of key material, expected {expected}")]
    UnexpectedKeyLength { expected: usize, received: usize },
}

impl From<CallError> for Error {
    fn from(error: CallError) -> Self {
        match error {
            CallError::Gcp(error) => Self::Gcp(error),
            CallError::Integrity(field) => Self::Integrity(field),
        }
    }
}

fn into_sized<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    crate::data_key::into_sized(bytes, |expected, received| Error::UnexpectedKeyLength {
        expected,
        received,
    })
}

/// Google Cloud KMS-backed data key source, bound to one `CryptoKey`
/// resource name.
///
/// Google Cloud KMS has no "generate data key" call, so this mints the
/// `N` bytes locally with the workspace CSPRNG and wraps them with
/// `cryptoKeys.encrypt`; the returned ciphertext *is* the
/// [`KeyId`](crate::KeyId), and [`RetrieveDataKey`] unwraps it with
/// `cryptoKeys.decrypt`. Neither call passes additional authenticated
/// data.
///
/// The binding is a `CryptoKey`, never a `CryptoKeyVersion`: encrypt uses
/// whichever version is primary at the time, and decrypt cannot be pointed
/// at a version at all — Google Cloud KMS's ciphertext says which version
/// produced it. Key rotation is therefore invisible here, and a `KeyId`
/// minted under an older version keeps working while that version is
/// enabled.
///
/// [`EncryptWithKey`]/[`DecryptWithKey`] are the same two calls used
/// directly, for small payloads that a caller wants encrypted under the
/// backend key itself rather than under a data key.
pub struct GcpDataKeySource<const N: usize> {
    client: KeyManagementService,
    crypto_key_name: String,
}

impl<const N: usize> GcpDataKeySource<N> {
    /// `crypto_key_name` is the full resource name of the `CryptoKey` this
    /// instance is bound to
    /// (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`), whose
    /// purpose must be `ENCRYPT_DECRYPT`.
    pub fn new(client: KeyManagementService, crypto_key_name: impl Into<String>) -> Self {
        Self {
            client,
            crypto_key_name: crypto_key_name.into(),
        }
    }

    /// One `cryptoKeys.encrypt` call, checksummed both ways.
    ///
    /// The plaintext is copied into the request body, which the SDK owns
    /// and this crate cannot zeroize; that copy lives until the request is
    /// dropped.
    /// One `cryptoKeys.encrypt` call, checksummed both ways.
    ///
    /// A non-empty `binding` goes as the additional authenticated data,
    /// checksummed like the plaintext. An **empty** binding sets no AAD at
    /// all rather than empty AAD: `Binding::EMPTY` means "nothing to bind",
    /// and omitting the field is what a caller that never passes a binding
    /// already sends.
    async fn encrypt_payload(
        &self,
        plaintext: Vec<u8>,
        binding: Binding<'_>,
    ) -> Result<Vec<u8>, Error> {
        let checksum = integrity::crc32c(&plaintext);
        let aad = binding.as_bytes().to_vec();
        let aad_checksum = integrity::crc32c(&aad);

        let response = integrity::checked_call(|| {
            let mut request = self
                .client
                .encrypt()
                .set_name(self.crypto_key_name.clone())
                .set_plaintext(plaintext.clone())
                .set_plaintext_crc32c(checksum);
            if !aad.is_empty() {
                request = request
                    .set_additional_authenticated_data(aad.clone())
                    .set_additional_authenticated_data_crc32c(aad_checksum);
            }
            request.send()
        })
        .await?;

        Ok(response.ciphertext.to_vec())
    }

    /// One `cryptoKeys.decrypt` call, checksummed both ways. The `binding`
    /// must be the one `encrypt_payload` sent, or Google refuses the call.
    async fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        binding: Binding<'_>,
    ) -> Result<Vec<u8>, Error> {
        let checksum = integrity::crc32c(ciphertext);
        let aad = binding.as_bytes().to_vec();
        let aad_checksum = integrity::crc32c(&aad);

        let response = integrity::checked_call(|| {
            let mut request = self
                .client
                .decrypt()
                .set_name(self.crypto_key_name.clone())
                .set_ciphertext(ciphertext.to_vec())
                .set_ciphertext_crc32c(checksum);
            if !aad.is_empty() {
                request = request
                    .set_additional_authenticated_data(aad.clone())
                    .set_additional_authenticated_data_crc32c(aad_checksum);
            }
            request.send()
        })
        .await?;

        Ok(response.plaintext.to_vec())
    }
}

impl<const N: usize> GenerateDataKey<N> for GcpDataKeySource<N> {
    type Error = Error;

    async fn generate_data_key(
        &self,
        binding: Binding<'_>,
    ) -> Result<GeneratedDataKey<N>, Self::Error> {
        let mut rng = SafeRand::from_entropy()?;
        let plaintext: Protected<[u8; N]> = Generatable::random(&mut rng)?;

        let ciphertext = self
            .encrypt_payload(plaintext.clone().risky_unwrap().to_vec(), binding)
            .await?;

        Ok(GeneratedDataKey {
            plaintext,
            key_id: KeyId::new(ciphertext),
        })
    }
}

impl<const N: usize> RetrieveDataKey<N> for GcpDataKeySource<N> {
    type Error = Error;

    /// Google Cloud KMS rebuilds a data key from the ciphertext plus IAM
    /// authorization alone — nothing the client holds is needed.
    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ServerOnly;

    /// Google Cloud KMS binds the additional authenticated data into the
    /// ciphertext and refuses a `decrypt` that presents different AAD.
    const BINDING: BindingSupport = BindingSupport::Bound;

    async fn retrieve_data_key(
        &self,
        key_id: &KeyId,
        binding: Binding<'_>,
    ) -> Result<Protected<[u8; N]>, Self::Error> {
        let plaintext = self.decrypt_payload(key_id.as_bytes(), binding).await?;

        Ok(Protected::new(into_sized(plaintext)?))
    }
}

impl<const N: usize> BatchGenerateDataKey<N> for GcpDataKeySource<N> {
    /// Google Cloud KMS has no batch primitive, so a batch is N separate
    /// `encrypt` calls, each over its own freshly generated key. See
    /// [`crate::PooledDataKeySource`] for the one-key-per-batch trade.
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;

    async fn generate_data_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        fan_out_generate(self, bindings).await
    }
}

impl<const N: usize> BatchRetrieveDataKey<N> for GcpDataKeySource<N> {
    async fn retrieve_data_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; N]>>, Self::Error> {
        dedup_retrieve(self, keys).await
    }
}

impl<const N: usize> EncryptWithKey for GcpDataKeySource<N> {
    type Error = Error;

    async fn encrypt(&self, plaintext: Protected<Vec<u8>>) -> Result<Vec<u8>, Self::Error> {
        self.encrypt_payload(plaintext.risky_unwrap(), Binding::EMPTY)
            .await
    }
}

impl<const N: usize> DecryptWithKey for GcpDataKeySource<N> {
    type Error = Error;

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Protected<Vec<u8>>, Self::Error> {
        Ok(Protected::new(
            self.decrypt_payload(ciphertext, Binding::EMPTY).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::integrity::crc32c;
    use crate::gcp::test_support::{ok, MockKms};
    use google_cloud_kms_v1::model::{DecryptResponse, EncryptResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";

    /// What a healthy Google Cloud KMS returns for an `encrypt`: a
    /// ciphertext with its own checksum, and confirmation that the
    /// request's checksum was verified.
    fn encrypt_response(ciphertext: Vec<u8>) -> EncryptResponse {
        EncryptResponse::new()
            .set_name(KEY)
            .set_ciphertext_crc32c(crc32c(&ciphertext))
            .set_ciphertext(ciphertext)
            .set_verified_plaintext_crc32c(true)
    }

    fn decrypt_response(plaintext: Vec<u8>) -> DecryptResponse {
        DecryptResponse::new()
            .set_plaintext_crc32c(crc32c(&plaintext))
            .set_plaintext(plaintext)
    }

    /// Wraps the plaintext as "ciphertext" by reversing it, so a test can
    /// assert the round trip carried the right bytes without pretending to
    /// encrypt anything.
    fn wrap(plaintext: &[u8]) -> Vec<u8> {
        plaintext.iter().rev().copied().collect()
    }

    #[tokio::test]
    async fn generate_sends_locally_minted_key_material_and_keeps_the_ciphertext_as_the_key_id() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&sent);

        let mut stub = MockKms::new();
        stub.expect_encrypt().times(1).returning(move |req, _| {
            assert_eq!(req.name, KEY);
            assert_eq!(req.plaintext.len(), 32);
            assert_eq!(req.plaintext_crc32c, Some(crc32c(&req.plaintext)));
            assert!(req.additional_authenticated_data.is_empty());
            *recorder.lock().unwrap() = req.plaintext.to_vec();
            ok(encrypt_response(wrap(&req.plaintext)))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();

        let plaintext = sent.lock().unwrap().clone();
        assert_eq!(generated.plaintext.risky_unwrap().to_vec(), plaintext);
        assert_eq!(generated.key_id.as_bytes(), wrap(&plaintext));
    }

    #[tokio::test]
    async fn two_generated_keys_differ() {
        let mut stub = MockKms::new();
        stub.expect_encrypt()
            .times(2)
            .returning(|req, _| ok(encrypt_response(wrap(&req.plaintext))));

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let first = source.generate_data_key(Binding::EMPTY).await.unwrap();
        let second = source.generate_data_key(Binding::EMPTY).await.unwrap();

        assert_ne!(
            first.plaintext.risky_unwrap(),
            second.plaintext.risky_unwrap()
        );
    }

    #[tokio::test]
    async fn retrieve_decrypts_the_key_id_back_into_key_material() {
        let mut stub = MockKms::new();
        stub.expect_encrypt()
            .times(1)
            .returning(|req, _| ok(encrypt_response(wrap(&req.plaintext))));
        stub.expect_decrypt().times(1).returning(|req, _| {
            assert_eq!(req.name, KEY);
            assert_eq!(req.ciphertext_crc32c, Some(crc32c(&req.ciphertext)));
            ok(decrypt_response(wrap(&req.ciphertext)))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();
        let retrieved = source
            .retrieve_data_key(&generated.key_id, Binding::EMPTY)
            .await
            .unwrap();

        assert_eq!(retrieved.risky_unwrap(), generated.plaintext.risky_unwrap());
        assert_eq!(
            <GcpDataKeySource<32> as RetrieveDataKey<32>>::RECONSTRUCTION,
            KeyReconstruction::ServerOnly
        );
    }

    #[tokio::test]
    async fn key_material_of_the_wrong_length_is_an_error_not_a_panic() {
        let mut stub = MockKms::new();
        stub.expect_decrypt()
            .times(1)
            .returning(|_, _| ok(decrypt_response(vec![7u8; 16])));

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let Err(error) = source
            .retrieve_data_key(&KeyId::new(vec![1, 2, 3]), Binding::EMPTY)
            .await
        else {
            panic!("expected a key-length error");
        };

        assert!(matches!(
            error,
            Error::UnexpectedKeyLength {
                expected: 32,
                received: 16
            }
        ));
    }

    #[tokio::test]
    async fn a_mangled_response_is_discarded_and_the_call_retried_once() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = MockKms::new();
        stub.expect_encrypt().times(2).returning(move |req, _| {
            let ciphertext = wrap(&req.plaintext);
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                // A checksum that does not describe the ciphertext.
                return ok(encrypt_response(ciphertext).set_ciphertext_crc32c(0));
            }
            ok(encrypt_response(ciphertext))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let generated = source.generate_data_key(Binding::EMPTY).await.unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            generated.key_id.as_bytes(),
            wrap(&generated.plaintext.risky_unwrap())
        );
    }

    #[tokio::test]
    async fn an_unverified_request_checksum_is_also_retried() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let mut stub = MockKms::new();
        stub.expect_encrypt().times(2).returning(move |req, _| {
            let response = encrypt_response(wrap(&req.plaintext));
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                return ok(response.set_verified_plaintext_crc32c(false));
            }
            ok(response)
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        assert!(source.generate_data_key(Binding::EMPTY).await.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_persistent_mismatch_is_an_integrity_error() {
        let mut stub = MockKms::new();
        stub.expect_encrypt().times(2).returning(|req, _| {
            ok(encrypt_response(wrap(&req.plaintext)).set_ciphertext_crc32c(0))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let Err(error) = source.generate_data_key(Binding::EMPTY).await else {
            panic!("expected an integrity error");
        };

        assert!(matches!(error, Error::Integrity("ciphertextCrc32c")));
    }

    #[tokio::test]
    async fn a_batch_generate_mints_one_key_per_item() {
        let mut stub = MockKms::new();
        stub.expect_encrypt()
            .times(3)
            .returning(|req, _| ok(encrypt_response(wrap(&req.plaintext))));

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let keys = source
            .generate_data_keys(&[Binding::EMPTY; 3])
            .await
            .unwrap();

        assert_eq!(keys.len(), 3);
        assert_ne!(keys[0].key_id, keys[1].key_id);
        assert_eq!(
            <GcpDataKeySource<32> as BatchGenerateDataKey<32>>::ISOLATION,
            KeyIsolation::PerValue
        );
    }

    #[tokio::test]
    async fn a_batch_retrieve_asks_for_each_distinct_key_id_once() {
        let mut stub = MockKms::new();
        stub.expect_decrypt()
            .times(2)
            .returning(|req, _| ok(decrypt_response(vec![req.ciphertext[0]; 32])));

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let ids = [
            KeyId::new(vec![1u8; 8]),
            KeyId::new(vec![2u8; 8]),
            KeyId::new(vec![1u8; 8]),
        ];
        let keys = source
            .retrieve_data_keys(&crate::data_key::unbound(&ids))
            .await
            .unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].clone().risky_unwrap(), [1u8; 32]);
        assert_eq!(keys[1].clone().risky_unwrap(), [2u8; 32]);
        assert_eq!(keys[2].clone().risky_unwrap(), [1u8; 32]);
    }

    #[tokio::test]
    async fn encrypt_and_decrypt_with_the_key_pass_the_payload_through() {
        let mut stub = MockKms::new();
        stub.expect_encrypt().times(1).returning(|req, _| {
            assert_eq!(req.plaintext_crc32c, Some(crc32c(&req.plaintext)));
            ok(encrypt_response(wrap(&req.plaintext)))
        });
        stub.expect_decrypt()
            .times(1)
            .returning(|req, _| ok(decrypt_response(wrap(&req.ciphertext))));

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);

        let ciphertext = source
            .encrypt(Protected::new(b"a short message".to_vec()))
            .await
            .unwrap();
        assert_eq!(ciphertext, wrap(b"a short message"));

        let plaintext = source.decrypt(&ciphertext).await.unwrap();
        assert_eq!(plaintext.risky_unwrap(), b"a short message".to_vec());
    }

    /// The binding has to reach Google as checksummed AAD on **both** calls:
    /// sent on encrypt and dropped on decrypt would make every key
    /// unretrievable, and the existing tests only pin the empty case.
    #[tokio::test]
    async fn the_binding_reaches_google_as_checksummed_aad_on_both_calls() {
        let aad = b"users/email".to_vec();

        let expected = aad.clone();
        let mut stub = MockKms::new();
        stub.expect_encrypt().times(1).returning(move |req, _| {
            assert_eq!(req.additional_authenticated_data, expected);
            assert_eq!(
                req.additional_authenticated_data_crc32c,
                Some(crc32c(&req.additional_authenticated_data)),
                "AAD is checksummed like the plaintext"
            );
            ok(encrypt_response(wrap(&req.plaintext)))
        });

        let expected = aad.clone();
        stub.expect_decrypt().times(1).returning(move |req, _| {
            assert_eq!(req.additional_authenticated_data, expected);
            assert_eq!(
                req.additional_authenticated_data_crc32c,
                Some(crc32c(&req.additional_authenticated_data))
            );
            ok(decrypt_response(vec![0u8; 32]))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);
        let binding = Binding::from("users/email");

        let generated = source.generate_data_key(binding).await.unwrap();
        let _ = source
            .retrieve_data_key(&generated.key_id, binding)
            .await
            .unwrap();
    }

    /// `dedup_retrieve` keys on the whole `(KeyId, Binding)` pair. The same
    /// id under two bindings is two different questions to a `Bound`
    /// backend — deduping on the id alone would ask once and hand the second
    /// item an answer it never asked for.
    #[tokio::test]
    async fn one_key_id_under_two_bindings_is_two_retrievals() {
        let mut stub = MockKms::new();
        stub.expect_decrypt().times(2).returning(|req, _| {
            // Material derived from the AAD, so a collapsed dedup would show
            // up as the wrong bytes rather than merely the wrong count.
            let first = req
                .additional_authenticated_data
                .first()
                .copied()
                .unwrap_or(0);
            ok(decrypt_response(vec![first; 32]))
        });

        let source = GcpDataKeySource::<32>::new(KeyManagementService::from_stub(stub), KEY);
        let key_id = KeyId::new(vec![1u8; 8]);

        let keys = source
            .retrieve_data_keys(&[
                (key_id.clone(), Binding::from("a")),
                (key_id, Binding::from("b")),
            ])
            .await
            .unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].clone().risky_unwrap(), [b'a'; 32]);
        assert_eq!(
            keys[1].clone().risky_unwrap(),
            [b'b'; 32],
            "the second binding got its own answer, not the first's"
        );
    }
}
