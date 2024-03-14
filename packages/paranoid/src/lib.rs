mod equatable;
mod exportable;
mod protected;
//mod digest;

pub mod debug;
pub use equatable::Equatable;
pub use exportable::Exportable;
pub use protected::Protected;

pub trait Paranoid: Sized {
    type Inner;

    // TODO: Don't make this part of the trait, just put a trait bound on the different types
    // We may need a method for internal use though
    fn new(x: Self::Inner) -> Self;

    // TODO: Use the private trait pattern to prevent direct access to the inner value
    fn inner(&self) -> &Self::Inner;

    // TODO: into_inner ?

    fn equatable(self) -> Equatable<Self> {
        Equatable(self)
    }

    fn exportable(self) -> Exportable<Self> {
        Exportable(self)
    }
}

// TODO: Add compile tests
