use crate::Paranoid;
use digest::generic_array::GenericArray;
use digest::Digest;
use digest::OutputSizeUser;

pub trait ProtectedDigestTmp {
    //: OutputSizeUser {
    type OutputType: Paranoid; // TODO: Also implements Acceptable<DefaultScope> + Acceptable<MyScope> + Acceptable<OtherScope> + ...

    // Required methods
    fn new() -> Self;
    fn new_with_prefix<T>(data: &T) -> Self
    where
        T: Paranoid,
        T::Inner: AsRef<[u8]>;
    fn update<T>(&mut self, data: &T)
    where
        T: Paranoid,
        T::Inner: AsRef<[u8]>;
    //fn chain_update(self, data: impl AsRef<[u8]>) -> Self;
    fn finalize(self) -> Self::OutputType;
    /*fn finalize_into(self, out: &mut Output<Self>);
    fn finalize_reset(&mut self) -> Output<Self>
       where Self: FixedOutputReset;
    fn finalize_into_reset(&mut self, out: &mut Output<Self>)
       where Self: FixedOutputReset;
    fn reset(&mut self)
       where Self: Reset;
    fn output_size() -> usize;
    fn digest(data: impl AsRef<[u8]>) -> Output<Self>;*/
}

pub struct ProtectedDigest<D: Digest>(D);

// TODO: Implement all of the Digest methods for ProtectedDigest
// TODO: Implement Usage scopes
// TODO: How can we force that the Digest types have Zeroize enabled? (Its a feature in the digest crate)
impl<D: Digest> ProtectedDigest<D> {
    pub fn new() -> Self {
        Self(D::new())
    }

    pub fn new_with_prefix<T>(data: &T) -> Self
    where
        T: Paranoid,
        T::Inner: AsRef<[u8]>,
    {
        Self(D::new_with_prefix(data.inner()))
    }

    pub fn update<T>(&mut self, data: &T)
    where
        T: Paranoid,
        T::Inner: AsRef<[u8]>,
    {
        self.0.update(data.inner())
    }

    pub fn finalize<T>(self) -> T
    where
        T: Paranoid + From<GenericArray<u8, <D as OutputSizeUser>::OutputSize>>,
    {
        let result = self.0.finalize();
        result.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protected;
    use sha2::{Sha256, Sha384};

    #[test]
    fn test_digest_sha256() {
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
