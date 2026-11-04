use vitaminc_password::AlphaNumericPassword;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

fn main() {
    let mut rng = SafeRand::from_seed([7; 32]);
    let _ = AlphaNumericPassword::<0>::random(&mut rng);
}
