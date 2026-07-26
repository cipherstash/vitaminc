use std::marker::PhantomData;

use crate::{Acceptable, Controlled, DefaultScope, Scope};
use digest::array::Array;
use digest::Digest;
use digest::FixedOutputReset;
use digest::Output;
use digest::OutputSizeUser;
use digest::Reset;
use zeroize::ZeroizeOnDrop;

/// A digest whose implementation wipes its internal state on drop.
///
/// Secret inputs enter through [`update`](Self::update) and secret outputs are
/// written directly into a [`Controlled`] destination by
/// [`finalize_into`](Self::finalize_into). Public input and output crossings
/// use explicitly named methods.
pub struct ProtectedDigest<D, InputScope = DefaultScope>(D, PhantomData<InputScope>)
where
    D: Digest + ZeroizeOnDrop;

// TODO: Implement Usage scopes
impl<D, InputScope> ProtectedDigest<D, InputScope>
where
    D: Digest + ZeroizeOnDrop,
    InputScope: Scope,
{
    pub fn new() -> Self {
        Self(D::new(), PhantomData)
    }

    pub fn new_with_prefix<T>(data: &T) -> Self
    where
        T: Controlled + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        Self(D::new_with_prefix(data.risky_ref()), PhantomData)
    }

    pub fn update<T>(&mut self, data: &T)
    where
        T: Controlled + Acceptable<InputScope>,
        T::Inner: AsRef<[u8]>,
    {
        self.0.update(data.risky_ref())
    }

    /// Add bytes that are intentionally public.
    ///
    /// This is an explicit escape from the protected-input channel for domain
    /// separators, framing, and other non-secret protocol data.
    pub fn update_public(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    /// Finalize directly into a protected destination without creating an
    /// ordinary intermediate digest array.
    pub fn finalize_into<'m, T>(self, out: &'m mut T)
    where
        T: Controlled,
        &'m mut Array<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T::Inner>,
    {
        let target: &mut Output<D> = out.inner_mut().into();
        self.0.finalize_into(target);
    }

    /// Finalize directly into an intentionally public destination.
    pub fn finalize_public_into<'m, T>(self, out: &'m mut T)
    where
        &'m mut Array<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T>,
    {
        let target: &mut Output<D> = out.into();
        self.0.finalize_into(target);
    }

    /// Finalize directly into a protected destination, then reset the digest.
    pub fn finalize_into_reset<'m, T>(&mut self, out: &'m mut T)
    where
        D: FixedOutputReset,
        T: Controlled,
        &'m mut Array<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T::Inner>,
    {
        let target: &mut Output<D> = out.inner_mut().into();
        Digest::finalize_into_reset(&mut self.0, target);
    }

    /// Finalize directly into an intentionally public destination, then reset
    /// the digest.
    pub fn finalize_public_into_reset<'m, T>(&mut self, out: &'m mut T)
    where
        D: FixedOutputReset,
        &'m mut Array<u8, <D as OutputSizeUser>::OutputSize>: From<&'m mut T>,
    {
        let target: &mut Output<D> = out.into();
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
}

impl<D, InputScope> Default for ProtectedDigest<D, InputScope>
where
    D: Digest + ZeroizeOnDrop,
    InputScope: Scope,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D, InputScope> ZeroizeOnDrop for ProtectedDigest<D, InputScope>
where
    D: Digest + ZeroizeOnDrop,
    InputScope: Scope,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protected;
    use sha2::{Sha256, Sha384};

    const SHA256_ZEROES_32: [u8; 32] = [
        102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20,
        133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37,
    ];

    const SHA384_ZEROES_32: [u8; 48] = [
        163, 143, 255, 75, 162, 108, 21, 228, 172, 156, 222, 140, 3, 16, 58, 200, 144, 128, 253,
        71, 84, 95, 222, 148, 70, 200, 241, 146, 114, 158, 171, 123, 208, 58, 77, 92, 49, 135, 247,
        95, 226, 167, 27, 14, 229, 10, 74, 64,
    ];

    #[test]
    fn protected_input_finalizes_directly_into_protected_sha256_output() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update(&Protected::new([0u8; 32]));
        let mut output = Protected::new([0u8; 32]);
        digest.finalize_into(&mut output);

        assert_eq!(output.risky_ref(), &SHA256_ZEROES_32);
    }

    #[test]
    fn public_input_finalizes_directly_into_public_sha256_output() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update_public(&[0u8; 32]);
        let mut output = [0u8; 32];
        digest.finalize_public_into(&mut output);

        assert_eq!(output, SHA256_ZEROES_32);
    }

    #[test]
    fn sha384_finalizes_directly_into_protected_and_public_outputs() {
        let mut protected_digest: ProtectedDigest<Sha384> = ProtectedDigest::new();
        protected_digest.update(&Protected::new([0u8; 32]));
        let mut protected_output = Protected::new([0u8; 48]);
        protected_digest.finalize_into(&mut protected_output);

        let mut public_digest: ProtectedDigest<Sha384> = ProtectedDigest::new();
        public_digest.update_public(&[0u8; 32]);
        let mut public_output = [0u8; 48];
        public_digest.finalize_public_into(&mut public_output);

        assert_eq!(protected_output.risky_ref(), &SHA384_ZEROES_32);
        assert_eq!(public_output, SHA384_ZEROES_32);
    }

    #[test]
    fn mixed_public_and_protected_updates_preserve_order() {
        let secret = Protected::new(*b"secret");
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update_public(b"domain");
        digest.update(&secret);
        let mut output = [0u8; 32];
        digest.finalize_public_into(&mut output);

        let mut reference = Sha256::new();
        reference.update(b"domain");
        reference.update(b"secret");
        assert_eq!(output.as_slice(), reference.finalize().as_slice());
    }

    #[test]
    fn protected_and_public_reset_finalization_reuses_the_digest() {
        let input = Protected::new(*b"repeat");
        let mut protected_digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        protected_digest.update(&input);
        let mut protected_first = Protected::new([0u8; 32]);
        protected_digest.finalize_into_reset(&mut protected_first);
        protected_digest.update(&input);
        let mut protected_second = Protected::new([0u8; 32]);
        protected_digest.finalize_into_reset(&mut protected_second);
        assert_eq!(protected_first.risky_ref(), protected_second.risky_ref());

        let mut public_digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        public_digest.update_public(b"repeat");
        let mut public_first = [0u8; 32];
        public_digest.finalize_public_into_reset(&mut public_first);
        public_digest.update_public(b"repeat");
        let mut public_second = [0u8; 32];
        public_digest.finalize_public_into_reset(&mut public_second);
        assert_eq!(public_first, public_second);
        assert_eq!(public_first.as_slice(), protected_first.risky_ref());
    }

    #[test]
    fn protected_prefix_matches_sha256() {
        let prefix = Protected::new(*b"prefix");
        let digest: ProtectedDigest<Sha256> = ProtectedDigest::new_with_prefix(&prefix);
        let mut output = [0u8; 32];
        digest.finalize_public_into(&mut output);

        assert_eq!(output.as_slice(), Sha256::digest(b"prefix").as_slice());
    }

    #[test]
    fn explicit_reset_discards_previous_input() {
        let mut digest: ProtectedDigest<Sha256> = ProtectedDigest::new();
        digest.update_public(b"discard");
        digest.reset();
        digest.update_public(b"kept");
        let mut output = [0u8; 32];
        digest.finalize_public_into(&mut output);

        assert_eq!(output.as_slice(), Sha256::digest(b"kept").as_slice());
        assert_eq!(ProtectedDigest::<Sha256>::output_size(), 32);
    }

    #[test]
    fn protected_digest_state_is_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ProtectedDigest<Sha256>>();
    }
}
