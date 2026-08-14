use vitaminc_protected::ProtectedRef;

fn main() {
    let bytes = [0_u8; 32];
    let _ = ProtectedRef(&bytes);
}
