//! CRC32C integrity checking for every Google Cloud KMS call.
//!
//! Google Cloud KMS carries a CRC32C checksum on every payload field of
//! every crypto operation: the caller sends `*_crc32c` alongside each
//! request field, and the response echoes both a `verified_*_crc32c`
//! flag (the server checked what it received) and a `*_crc32c` of its own
//! payload (the caller checks what it received). It is the one
//! per-call integrity handshake among the surveyed backends, and Google's
//! [data-integrity
//! guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines)
//! make the protocol explicit: "Discard the response in case of
//! non-matching checksum values, and perform a limited number of retries."
//!
//! Every adapter in this module therefore sends its checksums and routes
//! its call through [`checked_call`], which discards a response that fails
//! its check, retries once, and turns a second failure into
//! [`CallError::Integrity`]. Nothing about this reaches the capability
//! traits: a caller sees key material or an error, never a checksum.

use google_cloud_kms_v1::model::{
    AsymmetricSignResponse, DecryptResponse, EncryptResponse, MacSignResponse, MacVerifyResponse,
    PublicKey,
};
use thiserror::Error;

/// The CRC32C of a payload field, in the `int64` shape Google Cloud KMS's
/// request and response fields use. The value never exceeds 2^32-1, so the
/// widening conversion is lossless.
pub(super) fn crc32c(bytes: &[u8]) -> i64 {
    i64::from(crc32c::crc32c(bytes))
}

/// The response field whose integrity check failed. Carried through to
/// [`CallError::Integrity`] so an operator can tell which of a call's
/// several checksums is the one going wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Mismatch(pub(super) &'static str);

/// A Google Cloud KMS response that carries its own integrity fields.
pub(super) trait CheckIntegrity {
    /// `Ok(())` when every `verified_*_crc32c` flag is set and every
    /// payload checksum matches the payload actually received.
    fn check_integrity(&self) -> Result<(), Mismatch>;
}

/// The server confirmed it verified a request field's checksum. A `false`
/// here means the request's integrity was never established, so the
/// response is not trustworthy even if its own checksums match.
fn verified(flag: bool, field: &'static str) -> Result<(), Mismatch> {
    if flag {
        Ok(())
    } else {
        Err(Mismatch(field))
    }
}

/// A response payload matches the checksum sent with it. A missing
/// checksum counts as a mismatch: every successful crypto operation
/// populates it, so its absence is itself a sign of a mangled response.
fn matches(checksum: Option<i64>, payload: &[u8], field: &'static str) -> Result<(), Mismatch> {
    if checksum == Some(crc32c(payload)) {
        Ok(())
    } else {
        Err(Mismatch(field))
    }
}

impl CheckIntegrity for EncryptResponse {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        verified(self.verified_plaintext_crc32c, "verifiedPlaintextCrc32c")?;
        matches(self.ciphertext_crc32c, &self.ciphertext, "ciphertextCrc32c")
    }
}

impl CheckIntegrity for DecryptResponse {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        // `Decrypt` has no `verifiedCiphertextCrc32c`: a corrupted
        // ciphertext fails the request outright rather than coming back
        // as a flag.
        matches(self.plaintext_crc32c, &self.plaintext, "plaintextCrc32c")
    }
}

impl CheckIntegrity for MacSignResponse {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        verified(self.verified_data_crc32c, "verifiedDataCrc32c")?;
        matches(self.mac_crc32c, &self.mac, "macCrc32c")
    }
}

impl CheckIntegrity for MacVerifyResponse {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        verified(self.verified_data_crc32c, "verifiedDataCrc32c")?;
        verified(self.verified_mac_crc32c, "verifiedMacCrc32c")?;
        // `verifiedSuccessIntegrity` guards the verdict itself, and
        // Google's rule is to discard a response where it contradicts
        // `success`. Retrying resolves it; the `VerifyMac` caller never
        // sees this third state.
        if self.success == self.verified_success_integrity {
            Ok(())
        } else {
            Err(Mismatch("verifiedSuccessIntegrity"))
        }
    }
}

impl CheckIntegrity for AsymmetricSignResponse {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        // This adapter always signs a digest, never raw `data`, so
        // `verifiedDataCrc32c` is expected to be false and is not checked.
        verified(self.verified_digest_crc32c, "verifiedDigestCrc32c")?;
        matches(self.signature_crc32c, &self.signature, "signatureCrc32c")
    }
}

impl CheckIntegrity for PublicKey {
    fn check_integrity(&self) -> Result<(), Mismatch> {
        let key = self.public_key.as_ref().ok_or(Mismatch("publicKey"))?;
        matches(key.crc32c_checksum, &key.data, "publicKey.crc32cChecksum")
    }
}

/// Errors shared by every Google Cloud KMS call. Each adapter flattens
/// these into its own public error enum.
#[derive(Debug, Error)]
pub(super) enum CallError {
    #[error(transparent)]
    Gcp(#[from] google_cloud_kms_v1::Error),
    /// Two consecutive responses failed the same integrity check. Per
    /// Google's guidance this is no longer transient corruption to retry
    /// through: "A persistent mismatch may indicate an issue in your
    /// computation of the CRC32C checksum."
    #[error("Google Cloud KMS responses failed their {0} integrity check twice")]
    Integrity(&'static str),
}

/// Makes the call, and on a failed integrity check discards the response
/// and makes it exactly once more. A second failure is
/// [`CallError::Integrity`]; the caller never sees a response that did not
/// check out.
///
/// The call is a closure rather than a future so that the retry builds a
/// fresh request instead of polling a spent one.
pub(super) async fn checked_call<T, F, Fut>(mut call: F) -> Result<T, CallError>
where
    T: CheckIntegrity,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = google_cloud_kms_v1::Result<T>>,
{
    let first = call().await?;
    if first.check_integrity().is_ok() {
        return Ok(first);
    }

    let second = call().await?;
    second
        .check_integrity()
        .map_err(|Mismatch(field)| CallError::Integrity(field))?;
    Ok(second)
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_kms_v1::model::ChecksummedData;
    use std::cell::Cell;

    const PAYLOAD: &[u8] = b"a payload that travelled intact";

    fn good_encrypt() -> EncryptResponse {
        EncryptResponse::new()
            .set_ciphertext(PAYLOAD)
            .set_ciphertext_crc32c(crc32c(PAYLOAD))
            .set_verified_plaintext_crc32c(true)
    }

    #[test]
    fn crc32c_is_the_unsigned_checksum_widened() {
        // A known CRC32C value ("123456789" is the standard check vector).
        assert_eq!(crc32c(b"123456789"), 0xE3069283);
        assert!(crc32c(&[0xFF; 64]) >= 0);
    }

    #[test]
    fn an_intact_encrypt_response_checks_out() {
        assert_eq!(good_encrypt().check_integrity(), Ok(()));
    }

    #[test]
    fn an_encrypt_response_with_a_wrong_checksum_is_a_mismatch() {
        let response = good_encrypt().set_ciphertext_crc32c(crc32c(b"something else"));

        assert_eq!(
            response.check_integrity(),
            Err(Mismatch("ciphertextCrc32c"))
        );
    }

    #[test]
    fn an_encrypt_response_with_no_checksum_at_all_is_a_mismatch() {
        let response = EncryptResponse::new()
            .set_ciphertext(PAYLOAD)
            .set_verified_plaintext_crc32c(true);

        assert_eq!(
            response.check_integrity(),
            Err(Mismatch("ciphertextCrc32c"))
        );
    }

    #[test]
    fn an_unverified_request_checksum_is_a_mismatch() {
        let response = good_encrypt().set_verified_plaintext_crc32c(false);

        assert_eq!(
            response.check_integrity(),
            Err(Mismatch("verifiedPlaintextCrc32c"))
        );
    }

    #[test]
    fn decrypt_checks_its_plaintext_checksum() {
        let intact = DecryptResponse::new()
            .set_plaintext(PAYLOAD)
            .set_plaintext_crc32c(crc32c(PAYLOAD));
        assert_eq!(intact.check_integrity(), Ok(()));

        let mangled = DecryptResponse::new()
            .set_plaintext(PAYLOAD)
            .set_plaintext_crc32c(crc32c(b"other"));
        assert_eq!(mangled.check_integrity(), Err(Mismatch("plaintextCrc32c")));
    }

    #[test]
    fn mac_sign_checks_the_tag_and_the_request_flag() {
        let intact = MacSignResponse::new()
            .set_mac(PAYLOAD)
            .set_mac_crc32c(crc32c(PAYLOAD))
            .set_verified_data_crc32c(true);
        assert_eq!(intact.check_integrity(), Ok(()));

        assert_eq!(
            intact
                .clone()
                .set_verified_data_crc32c(false)
                .check_integrity(),
            Err(Mismatch("verifiedDataCrc32c"))
        );
        assert_eq!(
            intact.set_mac_crc32c(0).check_integrity(),
            Err(Mismatch("macCrc32c"))
        );
    }

    #[test]
    fn mac_verify_accepts_a_verdict_its_integrity_flag_agrees_with() {
        for verdict in [true, false] {
            let response = MacVerifyResponse::new()
                .set_success(verdict)
                .set_verified_success_integrity(verdict)
                .set_verified_data_crc32c(true)
                .set_verified_mac_crc32c(true);

            assert_eq!(response.check_integrity(), Ok(()));
        }
    }

    #[test]
    fn mac_verify_rejects_a_verdict_its_integrity_flag_contradicts() {
        for verdict in [true, false] {
            let response = MacVerifyResponse::new()
                .set_success(verdict)
                .set_verified_success_integrity(!verdict)
                .set_verified_data_crc32c(true)
                .set_verified_mac_crc32c(true);

            assert_eq!(
                response.check_integrity(),
                Err(Mismatch("verifiedSuccessIntegrity"))
            );
        }
    }

    #[test]
    fn asymmetric_sign_checks_the_digest_flag_not_the_data_flag() {
        let response = AsymmetricSignResponse::new()
            .set_signature(PAYLOAD)
            .set_signature_crc32c(crc32c(PAYLOAD))
            .set_verified_digest_crc32c(true)
            .set_verified_data_crc32c(false);
        assert_eq!(response.check_integrity(), Ok(()));

        assert_eq!(
            response.set_verified_digest_crc32c(false).check_integrity(),
            Err(Mismatch("verifiedDigestCrc32c"))
        );
    }

    #[test]
    fn a_public_key_checks_its_checksummed_data() {
        let response = PublicKey::new().set_public_key(
            ChecksummedData::new()
                .set_data(PAYLOAD)
                .set_crc32c_checksum(crc32c(PAYLOAD)),
        );
        assert_eq!(response.check_integrity(), Ok(()));

        let no_key = PublicKey::new();
        assert_eq!(no_key.check_integrity(), Err(Mismatch("publicKey")));

        let mangled = PublicKey::new().set_public_key(
            ChecksummedData::new()
                .set_data(PAYLOAD)
                .set_crc32c_checksum(crc32c(b"other")),
        );
        assert_eq!(
            mangled.check_integrity(),
            Err(Mismatch("publicKey.crc32cChecksum"))
        );
    }

    /// Feeds `checked_call` a scripted sequence of responses and counts
    /// the attempts it makes.
    async fn drive(script: &[EncryptResponse]) -> (Result<EncryptResponse, CallError>, usize) {
        let attempt = Cell::new(0usize);
        let result = checked_call(|| {
            let index = attempt.get();
            attempt.set(index + 1);
            let response = script[index].clone();
            async move { Ok(response) }
        })
        .await;

        (result, attempt.get())
    }

    #[tokio::test]
    async fn an_intact_response_is_returned_after_one_attempt() {
        let (result, attempts) = drive(&[good_encrypt()]).await;

        assert_eq!(result.unwrap().ciphertext, good_encrypt().ciphertext);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn a_mangled_response_is_discarded_and_the_call_retried_once() {
        let mangled = good_encrypt().set_ciphertext_crc32c(0);

        let (result, attempts) = drive(&[mangled, good_encrypt()]).await;

        assert!(result.is_ok());
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn two_mangled_responses_are_an_integrity_error() {
        let mangled = good_encrypt().set_ciphertext_crc32c(0);

        let (result, attempts) = drive(&[mangled.clone(), mangled]).await;

        assert!(matches!(
            result,
            Err(CallError::Integrity("ciphertextCrc32c"))
        ));
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn a_transport_error_is_not_retried() {
        let attempt = Cell::new(0usize);
        let result: Result<EncryptResponse, CallError> = checked_call(|| {
            attempt.set(attempt.get() + 1);
            async move {
                Err(google_cloud_kms_v1::Error::io(std::io::Error::other(
                    "boom",
                )))
            }
        })
        .await;

        assert!(matches!(result, Err(CallError::Gcp(_))));
        assert_eq!(attempt.get(), 1);
    }
}
