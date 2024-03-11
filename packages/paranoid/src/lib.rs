mod safe_eq;
mod protected;
//mod digest;
//mod generic_array;

pub mod debug;
pub use safe_eq::SafeEq;
pub use protected::Protected;

pub trait Paranoid {
    type Inner;

    fn new(x: Self::Inner) -> Self;

    // TODO: Use the private trait pattern to prevent direct access to the inner value
    fn inner(&self) -> &Self::Inner;
}

/*impl From<T> for Paranoid {
    fn from(x: T) -> Self {
        Self::new(x)
    }
}*/




