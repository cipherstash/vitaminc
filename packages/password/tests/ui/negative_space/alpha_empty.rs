use vitaminc_password::AlphaPassword;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

fn main() {
    let mut rng = SafeRand::from_seed([7; 32]);
    let _ = AlphaPassword::<0>::random(&mut rng);
}
