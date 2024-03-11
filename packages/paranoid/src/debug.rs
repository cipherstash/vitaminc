use crate::{exportable::Exportable, Equatable, Protected};

opaque_debug::implement!(Protected<T>);
opaque_debug::implement!(Equatable<T>);
opaque_debug::implement!(Exportable<T>);
