use digest::Output;
use zeroize::Zeroize;
use crate::Paranoid;
use sha2::Sha256;

use sha2::Digest;

pub trait ParanoidDigest { //: OutputSizeUser {
    type OutputType: Zeroize;

    // Required methods
    fn new() -> Self;
    fn new_with_prefix<T>(data: &Paranoid<T>) -> Self where T: Zeroize + AsRef<[u8]>;
    fn update<T>(&mut self, data: &Paranoid<T>) where T: Zeroize + AsRef<[u8]>;
    //fn chain_update(self, data: impl AsRef<[u8]>) -> Self;
    fn finalize(self) -> Paranoid<Self::OutputType>;
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

pub struct ParanoidSha256(Sha256);

impl ParanoidDigest for ParanoidSha256 {
    type OutputType = [u8; 32];

    fn new() -> Self {
        Self(Sha256::new())
    }

    fn new_with_prefix<T>(data: &Paranoid<T>) -> Self where T: Zeroize + AsRef<[u8]> {
        Self(Sha256::new_with_prefix(&data.0))
    }

    fn update<T>(&mut self, data: &Paranoid<T>) where T: Zeroize + AsRef<[u8]> {
        self.0.update(&data.0)
    }

    fn finalize(self) -> Paranoid<Self::OutputType> {
        let result: Output<_> = self.0.finalize();
        result.into()
    }
}