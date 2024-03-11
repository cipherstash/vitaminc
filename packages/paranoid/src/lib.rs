mod equatable;
mod protected;
mod exportable;
//mod digest;

pub mod debug;
pub use equatable::Equatable;
pub use protected::Protected;

pub trait Paranoid {
    type Inner;

    fn new(x: Self::Inner) -> Self;

    // TODO: Use the private trait pattern to prevent direct access to the inner value
    fn inner(&self) -> &Self::Inner;
}




