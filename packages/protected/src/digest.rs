use std::marker::PhantomData;

use crate::private::ParanoidPrivate;
use crate::{Acceptable, DefaultScope, Paranoid, Scope};
use digest::generic_array::GenericArray;
use digest::Digest;
use digest::FixedOutputReset;
use digest::Output;
use digest::OutputSizeUser;
use digest::Reset;

pub struct ProtectedDigest<D, InputScope = DefaultScope, OutputScope = DefaultScope>(D, PhantomData<InputScope>, PhantomData<OutputScope>);

// TODO: Implement Usage scopes
// TODO: How can we force that the Digest types have Zeroize enabled? (Its a feature in the digest crate but in the 0.11.0.pre versions)
impl<D: Digest, InputScope: Scope, OutputScope: Scope> ProtectedDigest<D, InputScope, OutputScope> {
    pub fn new() -> Self {
        Self(D::new(), PhantomData, PhantomData)
    }

    pub fn new_with_prefix<T>(data: &T) -> Self
    where
        T: Paranoid + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        Self(D::new_with_prefix(data.inner()), PhantomData, PhantomData)
    }

    pub fn update<T>(&mut self, data: &T)
    where
        T: Paranoid + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        self.0.update(data.inner())
    }

    pub fn finalize<T>(self) -> T
    where
        T: ParanoidPrivate + Acceptable<OutputScope>,
        T::Inner: From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
    {
        let result = self.0.finalize();
        let inner: T::Inner = result.into();
        T::init_from_inner(inner)
    }

    pub fn finalize_into<'m, T>(self, out: &'m mut T)
    where
        T: Paranoid + Acceptable<OutputScope>,
        &'m mut GenericArray<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T::Inner>,
    {
        let target: &mut Output<D> = out.inner_mut().into();
        self.0.finalize_into(target);
    }

    pub fn finalize_reset<T>(&mut self) -> T
    where
        D: FixedOutputReset,
        T: Paranoid + From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>> + Acceptable<OutputScope>,
    {
        let result = self.0.finalize_reset();
        result.into()
    }

    pub fn finalize_into_reset<'m, T>(&'m mut self, out: &'m mut T)
    where
        D: FixedOutputReset,
        T: Paranoid+ Acceptable<OutputScope>,
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
        T: Paranoid + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
        O::Inner: From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
        O: Paranoid + Acceptable<OutputScope>,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Protected, Usage};
    use sha2::{Sha256, Sha384};

    #[derive(Debug)]
    struct TestScope;
    impl Scope for TestScope {}

    #[test]
    fn test_digest_sha256_finalize() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let result: Protected<[u8; 32]> = digest.finalize();
        assert_eq!(
            result.equatable(),
            Protected::new([
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ])
            .equatable()
        );
    }

    #[test]
    fn test_digest_acceptable_input() {
        let mut digest: ProtectedDigest<Sha256, TestScope> = ProtectedDigest::new();
        digest.update(&Protected::new([0; 32]).for_scope::<TestScope>());
        let result: Protected<[u8; 32]> = digest.finalize();
        assert_eq!(
            result.equatable(),
            Protected::new([
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ])
            .equatable()
        );
    }

    // TODO: Test with Adapters
    #[test]
    fn test_digest_acceptable_output() {
        let mut digest: ProtectedDigest<Sha256, DefaultScope, TestScope> = ProtectedDigest::new();
        digest.update(&Protected::new([0; 32]));
        let result: Usage<Protected<[u8; 32]>, TestScope> = digest.finalize();
        assert_eq!(
            result.equatable(),
            Protected::new([
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ])
            .equatable()
        );
    }

    #[test]
    fn test_digest_sha256_finalize_into() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let mut result = Protected::new([0u8; 32]);
        digest.finalize_into(&mut result);
        assert_eq!(
            result.equatable(),
            Protected::new([
                102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8,
                151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37
            ])
            .equatable()
        );
    }

    #[test]
    fn test_digest_sha384() {
        let mut digest: ProtectedDigest<Sha384> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let result: Protected<[u8; 48]> = digest.finalize();
        assert_eq!(
            result.equatable(),
            Protected::new([
                163, 143, 255, 75, 162, 108, 21, 228, 172, 156, 222, 140, 3, 16, 58, 200, 144, 128,
                253, 71, 84, 95, 222, 148, 70, 200, 241, 146, 114, 158, 171, 123, 208, 58, 77, 92,
                49, 135, 247, 95, 226, 167, 27, 14, 229, 10, 74, 64,
            ])
            .equatable()
        );
    }
}
