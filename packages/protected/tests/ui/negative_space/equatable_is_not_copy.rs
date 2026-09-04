// `Equatable` wraps a secret whose zeroizing `Drop` reaches the bytes via
// `Equatable`'s field. A bitwise copy would leave an un-wiped duplicate
// behind, so `Equatable` itself must never be `Copy`.
//
// The payload is a bare `[u8; 32]` on purpose: it *is* `Copy`, so the only
// thing that can reject this is `Equatable`. (With a `Protected` payload the
// error would already come from `Protected: !Copy`, and a conditional `Copy`
// added to `Equatable` would go unnoticed.)
use vitaminc_protected::Equatable;

fn require_copy<T: Copy>() {}

fn main() {
    require_copy::<Equatable<[u8; 32]>>();
}
