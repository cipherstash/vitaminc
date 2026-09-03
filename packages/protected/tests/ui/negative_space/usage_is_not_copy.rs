// `Usage` carries a secret through its inner controlled wrapper, whose
// zeroizing `Drop` reaches the bytes via `Usage`'s field. A bitwise copy
// would leave an un-wiped duplicate behind, so `Usage` must never be `Copy`.
use vitaminc_protected::{DefaultScope, Protected, Usage};

fn require_copy<T: Copy>(_: &T) {}

fn main() {
    let secret: Usage<Protected<[u8; 32]>, DefaultScope> = Usage::new([0_u8; 32]);
    require_copy(&secret);
}
