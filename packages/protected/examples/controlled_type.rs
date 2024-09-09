use vitaminc_protected::{Controlled, ControlledInit, ControlledNew, Protected};

pub struct MyControlledType(Protected<[u8; 32]>);

impl ControlledInit for MyControlledType {
    type Inner = Protected<[u8; 32]>;

    fn init(safe: Self::Inner) -> Self {
        MyControlledType(safe)
    }

    fn into_inner(self) -> Self::Inner {
        self.0
    }
}

fn main() {
    let my_controlled_type = MyControlledType::new([0; 32]);
    let raw = my_controlled_type.risky_unwrap();
    assert_eq!(raw, [0; 32]);
}