use vitaminc_password::Password;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

fn main() {
    let mut rng = SafeRand::from_seed([7; 32]);
    let _ = Password::<0>::random(&mut rng);
}
