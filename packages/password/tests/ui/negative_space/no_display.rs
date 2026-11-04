use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};

fn display<T: std::fmt::Display>() {}

fn main() {
    display::<Password<20>>();
    display::<AlphaNumericPassword<22>>();
    display::<AlphaPassword<23>>();
}
