//! Status codes for the ABI's packed result encoding (see [`crate::abi`]).
//! Defined outside the wasm32-gated ABI module so native builds — the codec
//! unit tests and the fixture generator — can reference them too. The Go
//! host mirrors these values (`client.go`'s `status*` constants); they are
//! part of the guest/host contract and must not be renumbered. The
//! mappings from the library's errors onto them live here for the same
//! reason: they are pure, so a native test can pin every arm.

use vitaminc_aead::{DecryptError, EncryptError, Unencryptable};

/// AEAD open failure: wrong key, wrong AAD, or tampered ciphertext.
pub const STATUS_AUTH: u32 = 1;
/// Invalid input at the boundary: malformed transport bytes, a wrong-length
/// key, or a pointer/length pair that fails validation against linear
/// memory.
pub const STATUS_ENCODING: u32 = 2;
/// The handle is unknown (never issued, or already freed).
pub const STATUS_BAD_HANDLE: u32 = 3;
/// A cipher that could not be constructed, handle-id exhaustion, a caught
/// panic (unwind builds only), or any other unexpected internal failure.
pub const STATUS_INTERNAL: u32 = 4;
/// A non-empty array or object whose values are all passthrough: nothing in
/// it would be sealed, so nothing would authenticate the AAD or the keys,
/// and the guest refuses to encrypt it. The caller's input, not a guest
/// failure (#385).
pub const STATUS_NOTHING_SEALED: u32 = 5;

/// What an encryption refusal tells the host. A container with nothing
/// sealed is the caller's input, reported as its own status (#385); any
/// other shape the sink refuses is a malformed input; a cipher failure or a
/// miscounted leaf is internal.
pub fn encrypt_status<E>(error: EncryptError<E>) -> u32 {
    match error {
        EncryptError::Shape(refusal) => shape_status(refusal.reason()),
        EncryptError::Source(_) | EncryptError::Cipher(_) | EncryptError::Count(_) => {
            STATUS_INTERNAL
        }
    }
}

/// The status for a value the library refused to encrypt. The refusal also
/// says where in the value it happened; the status does not carry that.
pub fn shape_status(reason: Unencryptable) -> u32 {
    match reason {
        Unencryptable::SequenceHasNothingSealed | Unencryptable::MapHasNothingSealed => {
            STATUS_NOTHING_SEALED
        }
        _ => STATUS_ENCODING,
    }
}

/// What a decryption failure tells the host. The cipher's refusal, a tampered
/// empty marker and a leaf that does not parse are all one authentication
/// failure, so the status says nothing about which. Only the frame writer
/// refusing what it was given (an output too deep or too long to frame) is
/// an encoding error.
pub fn decrypt_status<E, C>(error: DecryptError<E, C>) -> u32 {
    match error {
        DecryptError::Cipher(_) | DecryptError::Auth | DecryptError::Malformed => STATUS_AUTH,
        DecryptError::Sink(_) => STATUS_ENCODING,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::frame::FrameWriteError;
    use vitaminc_aead::seal::LeafCount;
    use vitaminc_aead::{SourceError, Unspecified};

    #[test]
    fn every_shape_refusal_maps_to_the_documented_status() {
        let cases = [
            (
                Unencryptable::SequenceHasNothingSealed,
                STATUS_NOTHING_SEALED,
            ),
            (Unencryptable::MapHasNothingSealed, STATUS_NOTHING_SEALED),
            (Unencryptable::DuplicateKey, STATUS_ENCODING),
            (Unencryptable::TooDeep, STATUS_ENCODING),
        ];
        for (reason, status) in cases {
            assert_eq!(shape_status(reason), status, "{reason:?}");
        }
    }

    #[test]
    fn every_other_encrypt_failure_is_internal() {
        let cases: [(EncryptError<Unspecified>, u32); 3] = [
            (EncryptError::Cipher(Unspecified), STATUS_INTERNAL),
            (EncryptError::Source(SourceError::msg("x")), STATUS_INTERNAL),
            (EncryptError::Count(LeafCount::TooFew), STATUS_INTERNAL),
        ];
        for (error, status) in cases {
            let name = format!("{error:?}");
            assert_eq!(encrypt_status(error), status, "{name}");
        }
    }

    /// A refusal cannot be built by hand, so the `Shape` arm is reached
    /// through the library: a sequence whose only element is a passthrough
    /// seals nothing, and the host must hear that as its own status.
    #[test]
    fn a_real_refusal_reaches_the_host_as_nothing_sealed() {
        use vitaminc_aead::{plan, Context, Encrypt, Sink};

        struct Pass;
        impl Encrypt for Pass {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough("public")
            }
        }
        let error = plan::<_, Unspecified, _>(vec![Pass], Context::from_encoded(b"aad"))
            .err()
            .expect("a passthrough-only sequence is refused");
        assert!(matches!(error, EncryptError::Shape(_)), "{error:?}");
        assert_eq!(encrypt_status(error), STATUS_NOTHING_SEALED);
    }

    #[test]
    fn every_decrypt_failure_maps_to_the_documented_status() {
        let cases: [(DecryptError<FrameWriteError, Unspecified>, u32); 4] = [
            (DecryptError::Cipher(Unspecified), STATUS_AUTH),
            (DecryptError::Auth, STATUS_AUTH),
            (DecryptError::Malformed, STATUS_AUTH),
            (
                DecryptError::Sink(FrameWriteError::TooDeep),
                STATUS_ENCODING,
            ),
        ];
        for (error, status) in cases {
            let name = format!("{error:?}");
            assert_eq!(decrypt_status(error), status, "{name}");
        }
    }
}
