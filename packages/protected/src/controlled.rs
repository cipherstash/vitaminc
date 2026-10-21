pub use crate::Protected;
use crate::{private::ControlledPrivate, AsProtectedRef, ProtectedRef, ReplaceT};
use zeroize::Zeroize;

/// The operations every controlled wrapper (`Protected`, `Equatable`,
/// `Exportable`) provides.
///
/// # How the combinators hand over the inner value
///
/// `map`, `map_ok`, `zip` and `zip_ref` consume a controlled value and lend
/// its inner value to a closure as a shared reference. The closure reads the
/// value and builds a new one from it, which the combinator wraps. It never
/// owns the value, so it cannot move it anywhere: the consumed wrapper keeps
/// it, and wipes it when the combinator returns, including when the closure
/// panics.
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Controlled, Protected};
/// let len = Protected::new(vec![1u8, 2, 3]).map(|v| v.len());
/// assert_eq!(len.risky_unwrap(), 3);
/// ```
///
/// A conversion that would take the value by ownership builds its result
/// from the borrow instead. For bytes to text that is one copy, made straight
/// into the value the combinator wraps, and the error carries no bytes:
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Controlled, Protected};
/// let text = Protected::new(vec![104u8, 105])
///     .map_ok(|v| std::str::from_utf8(v).map(str::to_owned))
///     .expect("valid UTF-8");
/// assert_eq!(text.risky_unwrap(), "hi");
/// ```
///
/// A borrow does not stop a closure from copying or logging what it reads.
/// What it guarantees is that the wrapper keeps ownership, so the original is
/// always wiped, and anything the closure returns is wrapped again. An error
/// returned from `map_ok` is passed through as is, so do not build one that
/// carries the value.
///
/// # Changing the value in place
///
/// The `risky_update` family lends the inner value mutably, to change it in
/// place, for example to decrypt a buffer. A mutable borrow can still move
/// the value out (`core::mem::take`, `core::mem::replace`), which hands the
/// closure a bare value nothing wipes. That is why these methods carry the
/// `risky_` prefix, like `risky_unwrap`: review what each closure does with
/// the value.
pub trait Controlled: ControlledPrivate + Zeroize {
    type Inner: Zeroize;

    fn init_from_inner(x: Self::Inner) -> Self;
    fn inner_mut(&mut self) -> &mut Self::Inner;

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
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
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
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
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

    /// Map the inner value of this [Controlled] type.
    /// Conceptually similar to `Option::map`.
    ///
    /// The closure borrows the inner value; see the trait docs.
    ///
    /// # Example
    ///
    /// Map the inner value of a [Protected] to a new value.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let x = Protected::new(100u8);
    /// let y = x.map(|x| *x + 10);
    /// assert_eq!(y.risky_unwrap(), 110);
    /// ```
    fn map<B, F>(self, f: F) -> <Self as ReplaceT<B>>::Output
    where
        Self: Sized + ReplaceT<B>,
        F: FnOnce(&<Self as Controlled>::Inner) -> B,
        <Self as ReplaceT<B>>::Output: Controlled<Inner = B>,
        B: Zeroize,
    {
        // `self` is dropped, and so wiped, when this returns or unwinds.
        <Self as ReplaceT<B>>::Output::init_from_inner(f(self.risky_ref()))
    }

    /// Similar to `map` but the closure returns a `Result` with the new inner value.
    /// The result is a `Result` with the new [Controlled] type.
    ///
    /// The closure borrows the inner value; see the trait docs. An error the
    /// closure returns is passed through as is, so it must not carry the
    /// value.
    ///
    /// # Example
    ///
    /// Map the inner value of a [Protected] to a new value that is wrapped in a `Result`.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let x = Protected::new(vec![240, 159, 146, 150]);
    /// let y = x.map_ok(|v| std::str::from_utf8(v).map(str::to_owned));
    /// assert!(matches!(y, Ok(_)));
    /// assert_eq!(y.unwrap().risky_unwrap(), "💖");
    /// ```
    fn map_ok<B, F, E>(self, f: F) -> Result<<Self as ReplaceT<B>>::Output, E>
    where
        Self: Sized + ReplaceT<B>,
        F: FnOnce(&<Self as Controlled>::Inner) -> Result<B, E>,
        <Self as ReplaceT<B>>::Output: Controlled<Inner = B>,
        B: Zeroize,
    {
        // `self` is dropped, and so wiped, when this returns or unwinds.
        f(self.risky_ref()).map(<Self as ReplaceT<B>>::Output::init_from_inner)
    }

    /// Zip two [Controlled] values of the same type together with a function that combines them.
    ///
    /// The closure borrows both inner values; see the trait docs.
    ///
    /// # Example
    ///
    /// Add two [Protected] values together.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let x = Protected::new(1);
    /// let y = Protected::new(2);
    /// let z = x.zip(y, |x, y| *x + *y);
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
        F: FnOnce(&Self::Inner, &Other::Inner) -> Out,
    {
        // TODO: Use Replace private trait
        // `self` and `b` are dropped, and so wiped, when this returns or
        // unwinds.
        Protected::init_from_inner(f(self.risky_ref(), b.risky_ref()))
    }

    /// Like `zip` but the second argument is a reference.
    ///
    /// The closure borrows both inner values; see the trait docs.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let x = Protected::new(String::from("hello "));
    /// let y = Protected::new(String::from("world"));
    /// let z = x.zip_ref(&y, |x, y| format!("{x}{y}"));
    /// assert_eq!(z.risky_unwrap(), "hello world");
    /// ```
    ///
    fn zip_ref<'a, A, Other, Out, F>(
        self,
        other: &'a Other,
        f: F,
    ) -> <Self as ReplaceT<Out>>::Output
    where
        A: ?Sized + 'a,
        Self: Sized + ReplaceT<Out>,
        <Self as ReplaceT<Out>>::Output: Controlled<Inner = Out>,
        Other: AsProtectedRef<'a, A>,
        Out: Zeroize,
        F: FnOnce(&Self::Inner, &A) -> Out,
    {
        let arg: ProtectedRef<'a, A> = other.as_protected_ref();
        // `self` is dropped, and so wiped, when this returns or unwinds.
        <Self as ReplaceT<Out>>::Output::init_from_inner(f(self.risky_ref(), arg.inner_ref()))
    }

    /// Change the inner value in place, through a mutable borrow.
    ///
    /// This is risky because the closure can move the value out of the
    /// borrow (`core::mem::take`, `core::mem::replace`), and a value moved out
    /// is bare. See the trait docs.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// # use vitaminc::protected::{Controlled, Protected};
    /// let mut x = Protected::new([0u8; 4]);
    /// x.risky_update(|x| {
    ///   x.iter_mut().for_each(|x| {
    ///    *x += 1;
    ///  });
    /// });
    /// assert_eq!(x.risky_unwrap(), [1, 1, 1, 1]);
    /// ```
    ///
    fn risky_update<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut Self::Inner),
    {
        f(self.inner_mut());
    }

    /// Like `risky_update`, but the closure can fail.
    ///
    /// The error is returned as is. The value stays in the wrapper, possibly
    /// part changed, and is wiped when the wrapper drops, so a caller that
    /// gives up on an error can just drop it. The error must not carry the
    /// value.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// # use vitaminc::protected::{Controlled, Protected};
    /// let mut x = Protected::new(vec![1u8, 2, 3]);
    /// x.risky_try_update(|v| {
    ///     v.pop().ok_or("empty")?;
    ///     Ok::<_, &str>(())
    /// })
    /// .expect("not empty");
    /// assert_eq!(x.risky_unwrap(), [1, 2]);
    /// ```
    fn risky_try_update<F, E>(&mut self, f: F) -> Result<(), E>
    where
        F: FnOnce(&mut Self::Inner) -> Result<(), E>,
    {
        f(self.inner_mut())
    }

    /// Change the inner value in place, using the value of another
    /// [Controlled] value, which the closure borrows and which is wiped when
    /// this returns.
    ///
    /// This is risky for the same reason as `risky_update`.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.risky_update_with(y, |x, y| {
    ///    x.copy_from_slice(y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    /// TODO: Apply Usage trait bounds to prevent accidental broadening of scope
    /// e.g. `other` must have the same, or broader scope as `self`
    fn risky_update_with<Other, F>(&mut self, other: Other, mut f: F)
    where
        F: FnMut(&mut Self::Inner, &Other::Inner),
        Other: Controlled,
    {
        // `other` is dropped, and so wiped, when this returns or unwinds.
        f(self.inner_mut(), other.risky_ref());
    }

    /// Like `risky_update_with` but the second argument is a reference.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// # use vitaminc::protected::{Controlled, Protected};
    /// use vitaminc::protected::AsProtectedRef;
    ///
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.risky_update_with_ref(y.as_protected_ref(), |x, y| {
    ///   x.copy_from_slice(y);
    /// });
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    fn risky_update_with_ref<'a, A, F>(&mut self, other: ProtectedRef<'a, A>, mut f: F)
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
        <Self as Controlled>::Inner: AsRef<[I]>,
        I: Copy + Zeroize + 'a,
    {
        self.risky_ref()
            .as_ref()
            .iter()
            .copied()
            .map(Protected::new)
    }

    /// Replace the inner value with a new one.
    /// The new value must be `Self`.
    ///
    /// # Example
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Controlled, Protected};
    /// let mut x = Protected::new([0u8; 32]);
    /// let y = Protected::new([1u8; 32]);
    /// x.replace(y);
    /// assert_eq!(x.risky_unwrap(), [1u8; 32]);
    /// ```
    ///
    fn replace(&mut self, new: Self) -> Self
    where
        Self: Sized,
    {
        Self::init_from_inner(std::mem::replace(self.inner_mut(), new.risky_unwrap()))
    }

    /// Unwraps the inner value of the [Controlled] type.
    /// This is a risky operation because it consumes the [Controlled] type and returns the inner value
    /// negating the protections that the [Controlled] type provides.
    ///
    /// **Use with caution!**
    ///
    /// The returned value is bare: nothing wipes it any more. A result that
    /// is not used is dropped on the spot, unwiped, so the compiler warns
    /// when that happens.
    // TODO: Consider feature flagging this method
    #[must_use = "the bare value is dropped unwiped if it is not used"]
    fn risky_unwrap(self) -> Self::Inner;

    /// Provides a reference to the inner value.
    /// This is a risky operation because it bypasses the protections that the [Controlled] type provides.
    /// **Use with caution!**
    fn risky_ref(&self) -> &Self::Inner;

    /// Provides a mutable reference to the inner value.
    /// This is a risky operation because it bypasses the protections that the [Controlled] type provides.
    /// **Use with caution!**
    // TODO: This is an escape hatch until I find a way to work around it
    // It is needed for the seal_in_place methods for ring and aws-lc
    fn risky_inner_mut(&mut self) -> &mut Self::Inner {
        self.inner_mut()
    }
}

// TODO: Implement Collect for Protected (or Paranoid) so we can use collect() on iterators

#[cfg(test)]
mod tests {
    use crate::{Controlled, Equatable, Exportable, Protected};

    #[test]
    fn test_map_homogenous_inner() {
        let x = Protected::new(100u8);
        let y = x.map(|x| *x + 10);
        assert_eq!(y.risky_unwrap(), 110u8);
    }

    #[test]
    fn test_map_different_inner() {
        let x = Protected::new(100u8);
        let y: Protected<u16> = x.map(|x| u16::from(*x));
        assert_eq!(y.risky_unwrap(), 100u16);
    }

    #[test]
    fn test_map_adapter_homogenous_inner() {
        assert_eq!(
            Exportable::<Protected<u8>>::new(100)
                .map(|x| *x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Equatable::<Protected<u8>>::new(100)
                .map(|x| *x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Exportable::<Equatable<Protected<u8>>>::new(100)
                .map(|x| *x + 10)
                .risky_unwrap(),
            110u8
        );
        assert_eq!(
            Equatable::<Exportable<Protected<u8>>>::new(100)
                .map(|x| *x + 10)
                .risky_unwrap(),
            110u8
        );
    }

    #[test]
    fn test_map_adapter_different_inner() {
        assert_eq!(
            Exportable::<Protected<u8>>::new(100)
                .map(|x| u16::from(*x))
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Equatable::<Protected<u8>>::new(100)
                .map(|x| u16::from(*x))
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Exportable::<Equatable<Protected<u8>>>::new(100)
                .map(|x| u16::from(*x))
                .risky_unwrap(),
            100u16
        );
        assert_eq!(
            Equatable::<Exportable<Protected<u8>>>::new(100)
                .map(|x| u16::from(*x))
                .risky_unwrap(),
            100u16
        );
    }
}
