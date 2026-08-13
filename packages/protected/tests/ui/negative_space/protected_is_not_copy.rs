use vitaminc_protected::Protected;

fn require_copy<T: Copy>(_: &T) {}

fn main() {
    require_copy(&Protected::new([0_u8; 32]));
}
