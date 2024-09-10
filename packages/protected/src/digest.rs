use std::marker::PhantomData;

use crate::{Acceptable, Controlled, DefaultScope, Scope};
use digest::generic_array::GenericArray;
use digest::Digest;
use digest::FixedOutputReset;
use digest::Output;
use digest::OutputSizeUser;
use digest::Reset;

pub struct ProtectedDigest<D, InputScope = DefaultScope>(D, PhantomData<InputScope>);

// TODO: Implement Usage scopes
// TODO: How can we force that the Digest types have Zeroize enabled? (Its a feature in the digest crate but in the 0.11.0.pre versions)
impl<D: Digest, InputScope: Scope> ProtectedDigest<D, InputScope> {
    pub fn new() -> Self {
        Self(D::new(), PhantomData)
    }

    pub fn new_with_prefix<T>(data: &T) -> Self
    where
        T: Controlled + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        Self(D::new_with_prefix(data.inner()), PhantomData)
    }

    pub fn update<T>(&mut self, data: &T)
    where
        T: Controlled + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        self.0.update(data.inner())
    }

    pub fn finalize<T>(self) -> T
    where
        T: Controlled + From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
    {
        let result = self.0.finalize();
        result.into()
    }

    pub fn finalize_into<'m, T>(self, out: &'m mut T)
    where
        T: Controlled,
        &'m mut GenericArray<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T::Inner>,
    {
        let target: &mut Output<D> = out.inner_mut().into();
        self.0.finalize_into(target);
    }

    pub fn finalize_reset<T>(&mut self) -> T
    where
        D: FixedOutputReset,
        T: Controlled + From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
    {
        let result = self.0.finalize_reset();
        result.into()
    }

    pub fn finalize_into_reset<'m, T>(&'m mut self, out: &'m mut T)
    where
        D: FixedOutputReset,
        T: Controlled,
        &'m mut GenericArray<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T::Inner>,
    {
        let target: &mut Output<D> = out.inner_mut().into();
        Digest::finalize_into_reset(&mut self.0, target);
    }

    pub fn reset(&mut self)
    where
        D: Reset,
    {
        Digest::reset(&mut self.0);
    }

    pub fn output_size() -> usize {
        <D as Digest>::output_size()
    }

    pub fn digest<T, O>(data: &T) -> O
    where
        T: Controlled + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
        O: Controlled + From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl<D: Digest, InputScope: Scope> Default for ProtectedDigest<D, InputScope> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protected;
    use sha2::{Sha256, Sha384};

    #[test]
    fn test_digest_sha256_finalize() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let result: Protected<[u8; 32]> = digest.finalize();
        assert_eq!(
            result.risky_unwrap(),
            [
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ]
        );
    }

    #[test]
    fn test_digest_sha256_finalize_into() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let mut result = Protected::new([0u8; 32]);
        digest.finalize_into(&mut result);
        assert_eq!(
            result.risky_unwrap(),
            [
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ]
        );
    }

    #[test]
    fn test_digest_sha384() {
        let mut digest: ProtectedDigest<Sha384> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let result: Protected<[u8; 48]> = digest.finalize();
        assert_eq!(
            result.risky_unwrap(),
            [
                163, 143, 255, 75, 162, 108, 21, 228, 172, 156, 222, 140, 3, 16, 58, 200, 144, 128,
                253, 71, 84, 95, 222, 148, 70, 200, 241, 146, 114, 158, 171, 123, 208, 58, 77, 92,
                49, 135, 247, 95, 226, 167, 27, 14, 229, 10, 74, 64,
            ]
        );
    }
}
