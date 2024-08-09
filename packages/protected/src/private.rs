/// ParanoidPrivate is a private trait that is used to hide the inner value of a Paranoid type.
/// It is pub but within a private module.
pub trait ParanoidPrivate: Sized {
    type Inner;

    fn init_from_inner(x: Self::Inner) -> Self;
    fn inner(&self) -> &Self::Inner;
    fn inner_mut(&mut self) -> &mut Self::Inner;
    fn into_innner(self) -> Self::Inner;
}
