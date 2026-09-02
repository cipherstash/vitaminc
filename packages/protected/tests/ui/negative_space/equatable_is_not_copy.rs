use vitaminc_protected::{Equatable, Protected};

fn require_copy<T: Copy>(_: &T) {}

fn main() {
    let secret: Equatable<Protected<[u8; 32]>> = Equatable::new([0_u8; 32]);
    require_copy(&secret);
}
