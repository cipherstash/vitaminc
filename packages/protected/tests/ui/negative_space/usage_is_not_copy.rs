// `Usage` carries a secret through its inner controlled wrapper, whose
// zeroizing `Drop` reaches the bytes via `Usage`'s field. A bitwise copy of
// the scope wrapper would leave an un-wiped duplicate behind, so `Usage`
// itself must never be `Copy`.
//
// Both type arguments are `Copy` on purpose, so the only thing that can
// reject this is `Usage`. The payload is a bare `[u8; 32]` rather than a
// `Protected` (whose `!Copy` would mask a `Copy` added to `Usage`), and the
// scope is a local `Copy` marker rather than `DefaultScope` (a derived
// `Copy` on `Usage` would also require `Scope: Copy`, so with `DefaultScope`
// the case would keep failing for the wrong reason).
use vitaminc_protected::{Scope, Usage};

#[derive(Clone, Copy)]
struct CopyScope;
impl Scope for CopyScope {}

fn require_copy<T: Copy>() {}

fn main() {
    require_copy::<Usage<[u8; 32], CopyScope>>();
}
