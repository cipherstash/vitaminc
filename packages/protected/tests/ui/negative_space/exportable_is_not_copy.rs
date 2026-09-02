use vitaminc_protected::{Exportable, Protected};

fn require_copy<T: Copy>(_: &T) {}

fn main() {
    let secret: Exportable<Protected<[u8; 32]>> = Exportable::new([0_u8; 32]);
    require_copy(&secret);
}
