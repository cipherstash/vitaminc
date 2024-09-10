pub use crate::Protected;
use crate::{private::ControlledPrivate, AsProtectedRef, ProtectedRef, ReplaceT};
use zeroize::Zeroize;

pub trait Controlled: ControlledPrivate {
    /// Initialize a new instance of the [Controlled] type from the inner value.
    fn new(inner: Self::Inner) -> Self
    where
        Self: Sized,
    {
        Self::init_from_inner(inner)
    }

    /// Generate a new instance of the [Controlled] type from a function that returns the inner value.
    ///
    /// # Example
    ///
    /// Generate a new [Protected] from a function that returns an array.
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// fn array_gen<const N: usize>() -> [u8; N] {
    ///     let mut input: [u8; N] = [0; N];
    ///     input.iter_mut().enumerate().for_each(|(i, x)| {
    ///         *x = (i + 1) as u8;
    ///     });
    ///     input
    /// }
    /// let input: Protected<[u8; 8]> = Protected::generate(array_gen);
    /// assert_eq!(input.risky_unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
    /// ```
    /// // TODO: A Generate Array could handle the MaybeUninit stuff
    fn generate<F>(f: F) -> Self
    where
        Self: Sized,
        F: FnOnce() -> Self::Inner,
    {
        Self::init_from_inner(f())
    }

    /// Generate a new [Controlled] type from a function that returns a `Result` with the inner value.
    ///
    /// # Example
    ///
    /// Generate a new [Protected] from a function that returns a `Result` with the inner value.
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// use std::string::FromUtf8Error;
    ///
    /// let input: Result<Protected<String>, FromUtf8Error> = Protected::generate_ok(|| {
    ///    String::from_utf8(vec![1, 2, 3, 4, 5, 6, 7, 8])
    /// });
    /// ```
    ///
    fn generate_ok<F, E>(f: F) -> Result<Self, E>
    where
        Self: Sized,
        F: FnOnce() -> Result<Self::Inner, E>,
    {
        f().map(Self::init_from_inner)
    }

    /// Map the inner value of this [Controlled] type`.
    /// Conceptually similar to `Option::map`.
    ///
    /// # Example
    ///
    /// Map the inner value of a [Protected] to a new value.
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// let x = Protected::new(100u8);
    /// let y = x.map(|x| x + 10);
    /// assert_eq!(y.risky_unwrap(), 110);
    /// ```
    fn map<B, F>(self, f: F) -> <Self as ReplaceT<B>>::Output
    where
        Self: Sized + ReplaceT<B>,
        F: FnOnce(<Self as ControlledPrivate>::Inner) -> B,
        <Self as ReplaceT<B>>::Output: ControlledPrivate<Inner = B>,
        B: Zeroize,
    {
        <Self as ReplaceT<B>>::Output::init_from_inner(f(self.risky_unwrap()))
    }

    /// Zip two [Controlled] values of the same type together with a function that combines them.
    ///
    /// # Example
    ///
    /// Add two [Protected] values together.
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// let x = Protected::new(1);
    /// let y = Protected::new(2);
    /// let z = x.zip(y, |x, y| x + y);
    /// assert_eq!(z.risky_unwrap(), 3);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn zip<Other, Out, F>(self, b: Other, f: F) -> Protected<Out>
    where
        Self: Sized,
        Other: Controlled,
        Out: Zeroize,
        F: FnOnce(Self::Inner, Other::Inner) -> Out,
    {
        // TODO: Use Replace private trait
        Protected::init_from_inner(f(self.risky_unwrap(), b.risky_unwrap()))
    }

    /// Like `zip` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// let x = Protected::new(String::from("hello "));
    /// let y = Protected::new(String::from("world"));
    /// let z = x.zip_ref(&y, |x, y| x + y);
    /// assert_eq!(z.risky_unwrap(), "hello world");
    /// ```
    ///
    fn zip_ref<'a, A, Other, Out, F>(self, other: &'a Other, f: F) -> Protected<Out>
    where
        Self: Sized,
        A: ?Sized + 'a,
        Other: AsProtectedRef<'a, A>,
        Out: Zeroize,
        F: FnOnce(Self::Inner, &A) -> Out,
    {
        let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        Protected::init_from_inner(f(self.risky_unwrap(), arg.inner_ref()))
    }

    /// Similar to `map` but using references to that the inner value is updated in place.
    ///
    /// # Example
    ///
    /// ```
    /// # use vitaminc_protected::{Controlled, Protected};
    /// let mut x = Protected::new([0u8; 4]);
    /// x.update(|x| {
    ///   x.iter_mut().for_each(|x| {
    ///    *x += 1;
    ///  });
    /// });
    /// assert_eq!(x.risky_unwrap(), [1, 1, 1, 1]);
    /// ```
    ///
    fn update<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Self::Inner),
    {
        f(self.inner_mut());
    }

    /// Update the inner value with another [Controlled] value.
    /// The inner value of the second argument is passed to the closure.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_protected::{Controlled, Protected};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with(y, |x, y| {
    ///    x.copy_from_slice(&y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn update_with<Other, F>(&mut self, other: Other, mut f: F)
    where
        F: FnMut(&mut Self::Inner, Other::Inner),
        Other: Controlled,
    {
        // FIXME: There's a chance here that other will be dropped and not zeroized correctly
        // But not all Zeroize types are ZeroizeOnDrop - we may need to yield a wrapper type that Derefs to the inner value
        // Ditto for the zip method
        // Either that or just make sure the caller uses zeroize() on the other value :/
        f(self.inner_mut(), other.risky_unwrap());
    }

    /// Like `update_with` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// # use vitaminc_protected::{Controlled, Protected};
    /// use vitaminc_protected::AsProtectedRef;
    ///
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.update_with_ref(y.as_protected_ref(), |x, y| {
    ///   x.copy_from_slice(y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    fn update_with_ref<'a, A, F>(&mut self, other: ProtectedRef<'a, A>, mut f: F)
    where
        A: ?Sized + 'a,
        F: FnMut(&mut Self::Inner, &A),
    {
        f(self.inner_mut(), other.inner_ref());
    }

    /// Iterate over the inner value and wrap each element in a `Protected`.
    /// `I` must be `Copy` because [Protected] always takes ownership of the inner value.
    fn iter<'a, I>(&'a self) -> impl Iterator<Item = Protected<I>>
    where
        <Self as ControlledPrivate>::Inner: AsRef<[I]>,
        I: Copy + 'a,
    {
        self.inner().as_ref().iter().copied().map(Protected)
    }

    /// Unwraps the inner value of the [Controlled] type.
    /// This is a risky operation because it consumes the [Controlled] type and returns the inner value
    /// negating the protections that the [Controlled] type provides.
    ///
    /// **Use with caution!**
    ///
    // TODO: Consider feature flagging this method
    fn risky_unwrap(self) -> Self::Inner;
}

// TODO: Implement Collect for Protected (or Paranoid) so we can use collect() on iterators

#[cfg(test)]
mod tests {
    use crate::{Controlled, Equatable, Exportable, Protected};

    #[test]
    fn test_map_homogenous_inner() {
        let x = Protected::new(100u8);
        let y = x.map(|x| x + 10);
        assert_eq!(y.risky_unwrap(), 110u8);
    }

    #[test]
    fn test_map_different_inner() {
        let x = Protected::new(100u8);
        let y: Protected<u16> = x.map(u16::from);
        assert_eq!(y.risky_unwrap(), 100u16);
    }

    #[test]
    fn test_map_adapter_homogenous_inner() {
        assert_eq!(
            Exportable::<Protected<u8>>::new(100)
                .map(|x| x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Equatable::<Protected<u8>>::new(100)
                .map(|x| x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Exportable::<Equatable<Protected<u8>>>::new(100)
                .map(|x| x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Equatable::<Exportable<Protected<u8>>>::new(100)
                .map(|x| x + 10)
                .risky_unwrap(),
            110u8
        );
    }

    #[test]
    fn test_map_adapter_different_inner() {
        assert_eq!(
            Exportable::<Protected<u8>>::new(100)
                .map(u16::from)
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Equatable::<Protected<u8>>::new(100)
                .map(u16::from)
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Exportable::<Equatable<Protected<u8>>>::new(100)
                .map(u16::from)
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Equatable::<Exportable<Protected<u8>>>::new(100)
                .map(u16::from)
                .risky_unwrap(),
            100u16
        );
    }
}
