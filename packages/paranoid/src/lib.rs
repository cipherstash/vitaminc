mod equatable;
mod exportable;
mod protected;

mod private;
pub trait Paranoid: private::ParanoidPrivate {}

pub use equatable::Equatable;
pub use exportable::Exportable;
pub use protected::Protected;

// TODO: Add compile tests
