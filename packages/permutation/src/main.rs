use std::num::{NonZeroU16, NonZeroU8};

use permutation::{BitwisePermutation, Permutation, PermutationKey};
use protected::Protected;
use rand::SeedableRng;
use random::{Generatable, SafeRand};

fn main() {
    let mut rng = SafeRand::from_entropy();
    let perm_key: PermutationKey<16> = PermutationKey::generate(&mut rng).unwrap();
    let p = BitwisePermutation::new(&perm_key);
    dbg!(p.permute(Protected::new(NonZeroU16::new(193).unwrap())));

    let p2 = Permutation::new(&perm_key);
    let permuted = p2.permute(Protected::new([
        1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]));

    let e = permuted.exportable();
    println!("{}", serde_json::to_string(&e).unwrap());
}
