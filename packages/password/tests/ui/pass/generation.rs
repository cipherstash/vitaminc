use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};
use vitaminc_random::{Generatable, RandomError, SafeRand, SeedableRng};

fn main() -> Result<(), RandomError> {
    // Test fixtures may use a deterministic seed; examples use OS entropy.
    let mut rng = SafeRand::from_seed([7; 32]);
    let _ = Password::<20>::random(&mut rng)?;
    let _ = AlphaNumericPassword::<22>::random(&mut rng)?;
    let _ = AlphaPassword::<23>::random(&mut rng)?;
    let _ = Password::<32>::random(&mut rng)?;
    let _ = AlphaNumericPassword::<32>::random(&mut rng)?;
    let _ = AlphaPassword::<32>::random(&mut rng)?;
    // Resolve the default constructors without OS calls in this compile test.
    let _: fn() -> Result<Password<20>, RandomError> = Password::generate;
    let _: fn() -> Result<AlphaNumericPassword<22>, RandomError> = AlphaNumericPassword::generate;
    let _: fn() -> Result<AlphaPassword<23>, RandomError> = AlphaPassword::generate;
    Ok(())
}
