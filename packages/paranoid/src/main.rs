use paranoid::{Paranoid, Protected, SafeEq};

#[derive(Debug, PartialEq)]
struct Foo {
    key: SafeEq<Protected<[u8; 32]>>,
}

fn main() {
    let s: Protected<[u8; 32]> = Protected::new([0u8; 32]);
    println!("{:?}", s);
    let key = [0u8; 32];
    let foo = Foo {
        key: SafeEq::new(key),
    };
    println!("{:?}", foo);

    
}
