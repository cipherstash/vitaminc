use vitaminc_protected::{ControlledInit, ControlledMethods, ControlledNew, ControlledReplace, Protected};

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

impl ControlledMethods for MyControlledType {
    fn inner(&self) -> &Self::RawType {
        self.0.inner()
    }

    fn inner_mut(&mut self) -> &mut Self::RawType {
        self.0.inner_mut()
    }
}

impl<K> ControlledReplace<K> for MyControlledType {
    type Output = Self;
}

fn main() {
    let my_controlled_type = MyControlledType::new([0; 32]);
    my_controlled_type.map(|x| x);
    //let raw = my_controlled_type.risky_unwrap();
    //assert_eq!(raw, [0; 32]);
}