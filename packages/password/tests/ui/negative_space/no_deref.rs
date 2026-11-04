use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};

fn implicit<T: std::ops::Deref>() {}

fn main() {
    implicit::<Password<20>>();
    implicit::<AlphaNumericPassword<22>>();
    implicit::<AlphaPassword<23>>();
}
