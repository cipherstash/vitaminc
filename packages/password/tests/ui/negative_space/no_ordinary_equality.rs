use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};

fn comparable<T: PartialEq>() {}

fn main() {
    comparable::<Password<20>>();
    comparable::<AlphaNumericPassword<22>>();
    comparable::<AlphaPassword<23>>();
}
