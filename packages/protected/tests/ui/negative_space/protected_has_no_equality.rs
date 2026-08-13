use vitaminc_protected::Protected;

fn main() {
    let left = Protected::new(String::from("secret"));
    let right = Protected::new(String::from("secret"));
    let _ = left == right;
}
