use crate::backend::CipherKey;
use vitaminc_aead::{Encrypt, Unspecified};
use vitaminc_protected::{Controlled, Protected};
use vitaminc_random::{Generatable, RandomError, SafeRand};

/// 256-bit key type for use with symmetric encryption algorithms like AES-256-GCM.
/// Vitaminc does not support smaller key sizes to ensure quantum security and compatibility with AWS-LC.
///
/// `Encrypt` is derived: a newtype is transparent, so a `Key` seals exactly as
/// its `Protected<[u8; 32]>` does — which reaches the cipher's array entry
/// point still wrapped (see `Encrypt::encrypt_protected`). The 32 bytes are
/// never exposed as a bare `[u8; 32]` on the way in.
// SAFETY: Safe to implement Debug because the inner type is Protected, which does not leak sensitive data.
#[derive(Debug, Encrypt)]
#[cfg_attr(test, derive(Clone))]
pub struct Key(Protected<[u8; 32]>);

impl Key {
    pub(crate) fn cipher_key(&self) -> Result<CipherKey, Unspecified> {
        // SAFETY: the borrowed `&[u8; 32]` is consumed by `CipherKey::new` only
        // for the duration of the constructor; the backend cipher-key handle
        // holds an opaque copy thereafter, so no bare key material outlives this
        // call. `self.0` stays owned by `Protected` and is wiped on drop.
        CipherKey::new(self.0.risky_ref())
    }
}

impl From<[u8; 32]> for Key {
    fn from(key: [u8; 32]) -> Self {
        Self(Protected::new(key))
    }
}

impl Generatable for Key {
    fn random(rng: &mut SafeRand) -> Result<Self, RandomError> {
        Generatable::random(rng).map(Self)
    }
}

// Quickcheck `Arbitrary` impls for the property tests in `cipher::test` —
// gated to non-wasm32 alongside their consumers (see comment in `cipher.rs`).
// Split cfgs (not `all(test, …)`) so cargo-mutants recognises the test module.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod tests {
    use super::*;
    use quickcheck::Arbitrary;

    fn gen_array(g: &mut quickcheck::Gen) -> [u8; 32] {
        let mut array = [0u8; 32];
        for byte in array.iter_mut() {
            *byte = u8::arbitrary(g);
        }
        array
    }

    impl quickcheck::Arbitrary for Key {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Key::from(gen_array(g))
        }
    }

    /// A pair of keys guaranteed to be distinct at generation time. Property
    /// tests that depend on the keys differing (e.g. wrong-key rejection) use
    /// this so they cannot be flaky on the astronomically unlikely event that
    /// two independently random keys collide.
    #[derive(Clone, Debug)]
    pub(crate) struct DifferingKeyPair(pub Key, pub Key);

    impl quickcheck::Arbitrary for DifferingKeyPair {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let raw_a = gen_array(g);
            let mut raw_b = gen_array(g);
            while raw_a == raw_b {
                raw_b = gen_array(g);
            }
            Self(Key::from(raw_a), Key::from(raw_b))
        }
    }
}
