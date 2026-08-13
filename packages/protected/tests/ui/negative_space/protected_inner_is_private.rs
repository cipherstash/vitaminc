use vitaminc_protected::Protected;

fn main() {
    let secret = Protected::new(String::from("secret"));
    let _ = &secret.0;
}
