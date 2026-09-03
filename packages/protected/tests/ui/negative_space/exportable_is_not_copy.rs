// `Exportable` wraps a secret whose zeroizing `Drop` reaches the bytes via
// `Exportable`'s field. A bitwise copy would leave an un-wiped duplicate
// behind, so `Exportable` itself must never be `Copy`.
//
// The payload is a bare `[u8; 32]` on purpose: it *is* `Copy`, so the only
// thing that can reject this is `Exportable`. (With a `Protected` payload the
// error would already come from `Protected: !Copy`, and a conditional `Copy`
// added to `Exportable` would go unnoticed.)
use vitaminc_protected::Exportable;

fn require_copy<T: Copy>() {}

fn main() {
    require_copy::<Exportable<[u8; 32]>>();
}
