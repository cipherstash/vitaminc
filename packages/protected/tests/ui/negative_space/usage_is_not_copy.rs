// `Usage` carries a secret through its inner controlled wrapper, whose
// zeroizing `Drop` reaches the bytes via `Usage`'s field. A bitwise copy of
// the scope wrapper would leave an un-wiped duplicate behind, so `Usage`
// itself must never be `Copy`.
//
// The payload here is a bare `[u8; 32]` on purpose: it *is* `Copy`, so the
// only thing that can reject this call is `Usage` itself. (With a `Protected`
// payload the error would already come from `Protected: !Copy`, and a `Copy`
// impl added to `Usage` would go unnoticed.) `Zeroed` is the one constructor
// that admits a non-controlled payload.
use vitaminc_protected::{DefaultScope, Usage, Zeroed};

fn require_copy<T: Copy>(_: &T) {}

fn main() {
    let secret: Usage<[u8; 32], DefaultScope> = Usage::zeroed();
    require_copy(&secret);
}
