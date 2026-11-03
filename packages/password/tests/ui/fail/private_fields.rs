use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};
use vitaminc_protected::Protected;

fn main() {
    let _ = Password(Protected::new(['a'; 20]));
    let _ = AlphaNumericPassword(Password::generate().unwrap());
    let _ = AlphaPassword(Password::generate().unwrap());
}
