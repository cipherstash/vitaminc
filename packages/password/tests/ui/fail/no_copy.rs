use vitaminc_password::{AlphaNumericPassword, AlphaPassword, Password};

fn copy<T: Copy>() {}

fn main() {
    copy::<Password<20>>();
    copy::<AlphaNumericPassword<22>>();
    copy::<AlphaPassword<23>>();
}
