use vitaminc_protected::Controlled;
use zeroize::Zeroize;

struct Untrusted(Vec<u8>);

impl Zeroize for Untrusted {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Controlled for Untrusted {
    type Inner = Vec<u8>;

    fn risky_unwrap(self) -> Self::Inner { self.0 }
    fn init_from_inner(inner: Self::Inner) -> Self { Self(inner) }
    fn risky_ref(&self) -> &Self::Inner { &self.0 }
    fn inner_mut(&mut self) -> &mut Self::Inner { &mut self.0 }
}

fn main() {}
