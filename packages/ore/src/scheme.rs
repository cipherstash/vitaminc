//! The sealed order plaintext, the trait a scheme implements to encrypt
//! it, and the space a caller encrypts through.
//!
//! A caller opens a space on a scheme, with the target every value in it
//! is encoded as and the context its terms compare within, and encrypts
//! values: `scheme.target(I32).context(("orders", "total")).encrypt(42i16)`.
//! It never sees the encoding. A scheme opens a space once, under the
//! salt the space derives, and encrypts the sealed [`OrderPlaintext`]s of
//! that space with what it derived; it never sees bytes that skipped the
//! encoding (the only way to make a plaintext is [`order`]) or a salt it
//! could derive differently from another scheme.

use core::cmp::Ordering;
use core::fmt;
use std::sync::OnceLock;

use vitaminc_aead::plaintext::{self, SourceError};
use vitaminc_aead::{Encrypt, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_context::{Context, IntoContext};
use vitaminc_normalize::NormalizeError;
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};

use crate::target::{FitsIn, OwnTarget, StaticTarget, Supports, Target};
use crate::{order, OrderTarget};

/// The label every salt this crate derives leads with.
const SALT_LABEL: &[u8] = b"vitaminc/ore/v1";

/// One scalar's order term before encryption: bytes whose order is the
/// value's order, encoded as the target they were made for.
///
/// Only [`order`] builds one, so a scheme can rely on the bytes being the
/// encoding of their target, and on there being at least one: a
/// fixed-width target encodes to its width, and text and bytes start with
/// [`VARIABLE_WIDTH_MARKER`](crate::VARIABLE_WIDTH_MARKER). A caller
/// never needs one: [`OrderSpace::encrypt`] takes the value itself.
/// `Debug` shows the domain and width and masks the bytes.
#[derive(OpaqueDebug)]
pub struct OrderPlaintext {
    #[non_sensitive]
    target: OrderTarget,
    bytes: Protected<Vec<u8>>,
}

impl OrderPlaintext {
    pub(crate) fn new(target: OrderTarget, bytes: Protected<Vec<u8>>) -> Self {
        debug_assert!(
            target.width().is_none_or(|w| w == bytes.risky_ref().len()),
            "{target:?} encodes to its width"
        );
        debug_assert!(
            !bytes.risky_ref().is_empty(),
            "an order plaintext is never empty"
        );
        Self { target, bytes }
    }

    /// The target the bytes were encoded as.
    pub fn target(&self) -> OrderTarget {
        self.target
    }

    /// The frozen domain label, one of the [`domain`](crate::domain)
    /// constants: the target's.
    pub fn domain(&self) -> &'static str {
        self.target.domain()
    }

    /// The width every term of this target has, or `None` for text and
    /// bytes, whose terms vary in length. A fixed-width scheme says which
    /// widths it takes in [`Supports::supports`], so it refuses a target
    /// rather than a value, and never sees a plaintext of another.
    pub fn width(&self) -> Option<usize> {
        self.target.width()
    }

    /// The term's bytes, protected, never empty. A scheme reads them with
    /// [`risky_ref`](Controlled::risky_ref) and nothing else should.
    pub fn bytes(&self) -> &Protected<Vec<u8>> {
        &self.bytes
    }
}

/// Why a space produced no term. Never includes plaintext.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrderError<E> {
    /// The scalar has no order term as the space's target: no order for
    /// its kind, another kind than the target, outside the target, not
    /// valid for its logical type, or text with a code point unassigned
    /// in Unicode 16.
    #[error("no order term: {0}")]
    Term(#[from] NormalizeError),
    /// The value is a sequence, a map or a passthrough, which has no
    /// single term. Walk it with [`order_terms`](crate::order_terms).
    #[error("a container has no single order term; walk it for one per scalar")]
    NotScalar,
    /// The value could not be read: its source failed before any term
    /// was made.
    #[error("the value could not be read: {0}")]
    Source(SourceError),
    /// The scheme does not take terms of this target, chosen while the
    /// program ran: a fixed-width scheme given text, or a width above its
    /// limit. A target named when the program is compiled is checked
    /// then, through [`Supports`], and never reaches this.
    #[error("{scheme} has no order term for {domain}")]
    Unsupported {
        /// The scheme's [`NAME`](OrderScheme::NAME).
        scheme: &'static str,
        /// The target's domain label.
        domain: &'static str,
    },
    /// The scheme's own failure.
    #[error("the order scheme failed: {0}")]
    Backend(E),
}

/// An order scheme: encrypts one sealed plaintext so that the terms still
/// compare.
///
/// A scheme implements [`open`](OrderScheme::open), which derives what it
/// keeps for one space from the salt, [`encrypt_plaintext`](OrderScheme::encrypt_plaintext)
/// over that, and [`compare`](OrderScheme::compare); and it says which
/// targets it takes through [`Supports`]. A caller does not call any of
/// them: it opens a space with [`OrderEncrypt::target`], which every
/// scheme has, and encrypts values there. The space derives the salt the
/// scheme binds, so no scheme can leave a part of it out, opens the
/// scheme under it once, and refuses a target the scheme does not take
/// before the scheme sees it.
///
/// Terms compare only between terms of the same scheme, key, target and
/// context: a space. The scheme keeps its own comparison (CLLW ORE and
/// block ORE do not compare byte by byte) in [`compare`](Self::compare),
/// and its own stored bytes through `AsRef<[u8]>`. A term is not `Ord`:
/// that would promise an order between any two terms, and no term carries
/// which space it came from, so two terms of different spaces would
/// compare as noise and break every sort and tree that trusted the
/// promise.
///
/// Implemented by the scheme crates behind a `vitaminc` feature, and by a
/// mock in this crate's tests. An implementation reads the plaintext's
/// [`bytes`](OrderPlaintext::bytes) and binds the salt through what
/// [`open`](Self::open) derived from it; it never pads or truncates. The bytes are never empty (a variable-width encoding starts
/// with [`VARIABLE_WIDTH_MARKER`](crate::VARIABLE_WIDTH_MARKER)), so a
/// scheme can rely on running its keyed primitive at least once, and
/// every term it makes must depend on the key and the salt: a term that
/// is the same under every key could be written into any index by
/// anyone. `test_support` (behind the `test-support` feature) checks a
/// real scheme for this.
pub trait OrderScheme {
    /// The scheme's name, bound into every term's salt and named in its
    /// refusals: `"cllw-ore"`, `"cllw-ope"`, `"block-ore"`.
    const NAME: &'static str;

    /// What one term encrypts to.
    type Term: AsRef<[u8]>;

    /// The scheme's own failure. [`Infallible`](core::convert::Infallible)
    /// for a scheme that cannot fail once keyed.
    type Error: core::error::Error + Send + Sync + 'static;

    /// What the scheme keeps for one space: whatever it derives from the
    /// salt, so that it is derived for the space rather than for every
    /// term. Block ORE keeps the keys and cipher it derives under the
    /// salt; a scheme that passes the salt straight to its primitive, as
    /// CLLW does, keeps the salt itself (`Context<'static>`).
    ///
    /// vitaminc places no bound on it and applies no wipe when it is
    /// dropped, with the [`OrderSpace`] or as the loser of a race to open
    /// (see [`open`](Self::open)). A `Space` that holds derived keys keeps
    /// them in [`Protected`] or implements `ZeroizeOnDrop` itself.
    ///
    /// An [`OrderSpace`] holds a reference to the scheme and one of these,
    /// so it is `Send` when the scheme is `Sync` and this is `Send`, and
    /// `Sync` when this is `Sync` too. A scheme that keeps a random number
    /// generator behind a `RefCell` here has a space per thread.
    type Space;

    /// Open a space: derive what [`Space`](Self::Space) keeps, binding
    /// `salt`: `PAE("vitaminc/ore/v1", NAME, domain, context)`, which the
    /// space derives. Called when a space's first value is encrypted, or
    /// from [`OrderSpace::open`], and not for every term.
    ///
    /// It may run more than once for one space: again after it fails, and
    /// by more than one thread at once if they race to the first value,
    /// in which case one result is kept and the rest dropped. So it must
    /// be a pure derivation from `salt` and the scheme's key, with no
    /// side effect that assumes it runs once.
    ///
    /// # Errors
    ///
    /// The scheme's own failure: seeding its random number generator,
    /// say. The space reports it from every encryption, and tries again
    /// on the next.
    fn open(&self, salt: &Context<'_>) -> Result<Self::Space, Self::Error>;

    /// Encrypt a sealed plaintext of `space`, which [`open`](Self::open)
    /// made under the space's salt.
    ///
    /// The plaintext is of a target the scheme [`Supports`]: the space
    /// checks before calling. So the only failure is the scheme's own.
    ///
    /// # Errors
    ///
    /// The scheme's own failure: its random number generator, say.
    fn encrypt_plaintext(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<Self::Term, Self::Error>;

    /// The order of two terms of one space, as the order of the values
    /// they encrypt. Needs no key: that is what makes the scheme an order
    /// scheme.
    ///
    /// Over the terms of one space this is a total order, so a caller may
    /// sort with it. `None` says the two cannot be compared: one is not a
    /// term of this scheme, or the two were not made to compare (block
    /// ORE under different padding). A scheme returns `None` wherever it
    /// can tell, and never falls back to comparing bytes it cannot order.
    /// It cannot tell everything: two well-formed terms of different
    /// spaces may compare as noise, so a caller keeps a space's terms
    /// together, as [`OrderSpace::compare`] says.
    ///
    /// The noise is in the direction, never in equality. `Some(Equal)`
    /// means the two terms encrypt one value in one space, up to the
    /// scheme's own collision bound: a term that lacks every block, or
    /// that ignores its key or salt, compares equal to one of another
    /// space, and the `test_support` checks fail it for that. Block ORE
    /// keeps this because equality needs every block's keyed tag to
    /// agree, and an OPE because equality is equal bytes. A scheme that
    /// cannot keep it answers `None` across spaces instead.
    fn compare(a: &Self::Term, b: &Self::Term) -> Option<Ordering>;
}

/// What a caller does with any [`OrderScheme`]: name a target, a context,
/// or just a value, and get terms. Implemented for every scheme and for
/// nothing else, so a scheme cannot change how a space binds its terms.
///
/// Every step of the chain is usable. A target alone is a space under the
/// empty context; a context alone takes values whose Rust type says the
/// target; a value alone uses both defaults.
///
/// ```
/// use std::cmp::Ordering;
/// use vitaminc_ore::target::I32;
/// use vitaminc_ore::{OrderEncrypt, OrderTarget};
/// # use vitaminc_ore::{Context, OrderPlaintext, OrderScheme};
/// # /// Keeps the bytes as they are, for the example. Any scheme will do.
/// # struct Clear;
/// # impl OrderScheme for Clear {
/// #     const NAME: &'static str = "clear";
/// #     type Term = Vec<u8>;
/// #     type Error = core::convert::Infallible;
/// #     type Space = ();
/// #     fn open(&self, _: &Context<'_>) -> Result<(), Self::Error> {
/// #         Ok(())
/// #     }
/// #     fn encrypt_plaintext(&self, _: &(), p: &OrderPlaintext) -> Result<Vec<u8>, Self::Error> {
/// #         use vitaminc_protected::Controlled;
/// #         Ok(p.bytes().risky_ref().clone())
/// #     }
/// #     fn compare(a: &Vec<u8>, b: &Vec<u8>) -> Option<Ordering> {
/// #         Some(a.cmp(b))
/// #     }
/// # }
/// # vitaminc_ore::supports_every_target!(Clear);
/// # let scheme = Clear;
///
/// // Held, for many values.
/// let quantity = scheme.target(I32).context(("orders", "quantity"));
/// let a = quantity.encrypt(42i16)?; // an i16 always fits an i32
/// let b = quantity.encrypt_checked(43i64)?; // an i64 is checked
/// assert_eq!(quantity.compare(&a, &b), Some(Ordering::Less));
///
/// // One-shot chains.
/// scheme.target(I32).encrypt(42i16)?; // context ()
/// scheme.context("tenant-7").encrypt(42i64)?; // the type's own target, I64
/// scheme.encrypt(42i64)?; // own target, no context
///
/// // A target chosen while the program runs, as an index layer needs.
/// let index = scheme.target(OrderTarget::I32).context("ctx");
/// index.encrypt_checked(42i64)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait OrderEncrypt: OrderScheme {
    /// A space of `target` values under the empty context: a marker from
    /// [`target`](crate::target), or an [`OrderTarget`] chosen while the
    /// program runs. Chain [`context`](OrderSpace::context) to bind one.
    ///
    /// Compiles only for a target this scheme [`Supports`].
    fn target<T: Target>(&self, target: T) -> OrderSpace<'_, Self, T>
    where
        Self: Supports<T> + Supports<OrderTarget>,
    {
        OrderSpace::new(self, target, &().into_context().encode())
    }

    /// The terms that compare within `context` (a table and column, a
    /// tenant, whatever they must compare within): chain
    /// [`target`](OrderContext::target), or encrypt a value whose type is
    /// its target.
    fn context<'a, C: IntoContext<'a>>(&self, context: C) -> OrderContext<'_, Self> {
        OrderContext {
            scheme: self,
            context: context.into_context().encode().into_owned(),
        }
    }

    /// Encrypt a value as the target its Rust type is, under the empty
    /// context: `scheme.target(V::Target).encrypt(value)`. A one-shot
    /// chain makes a space per call, so the scheme opens per value; hold
    /// `scheme.target(..).context(..)` to derive once for many values.
    ///
    /// # Errors
    ///
    /// The scheme's own failure, and nothing else: the value always fits.
    fn encrypt<V>(&self, value: V) -> Result<OrderTerm<Self::Term, V::Target>, Self::Error>
    where
        V: OwnTarget + FitsIn<V::Target>,
        Self: Supports<V::Target> + Supports<OrderTarget>,
    {
        self.target(V::Target::default()).encrypt(value)
    }

    /// Encrypt a value as the target its Rust type is, checking it while
    /// the program runs, under the empty context:
    /// `scheme.target(V::Target).encrypt_checked(value)`.
    ///
    /// # Errors
    ///
    /// As [`OrderSpace::encrypt_checked`].
    #[allow(clippy::type_complexity)]
    fn encrypt_checked<V: OwnTarget>(
        &self,
        value: V,
    ) -> Result<OrderTerm<Self::Term, V::Target>, OrderError<Self::Error>>
    where
        Self: Supports<V::Target> + Supports<OrderTarget>,
    {
        self.target(V::Target::default()).encrypt_checked(value)
    }

    /// `scheme.target(target).context(context)`, as the 0.6 API spelt it.
    #[deprecated(since = "0.7.0", note = "use `scheme.target(target).context(context)`")]
    fn column<'a, C: IntoContext<'a>>(
        &self,
        target: OrderTarget,
        context: C,
    ) -> OrderSpace<'_, Self, OrderTarget>
    where
        Self: Supports<OrderTarget>,
    {
        self.target(target).context(context)
    }
}

impl<S: OrderScheme + ?Sized> OrderEncrypt for S {}

/// `PAE("vitaminc/ore/v1", scheme, domain, context)`. Leading with this
/// crate's own label keeps it apart from any context another crate
/// derives from the same parts.
fn salt(scheme: &str, target: OrderTarget, context: &Context<'_>) -> Context<'static> {
    Context::pae(&[
        SALT_LABEL,
        scheme.as_bytes(),
        target.domain().as_bytes(),
        context.as_bytes(),
    ])
}

/// A scheme and a context, with the target still to come: from
/// [`OrderEncrypt::context`]. `Debug` masks the scheme, whose key it
/// holds.
#[derive(OpaqueDebug)]
pub struct OrderContext<'s, S: OrderScheme + ?Sized> {
    scheme: &'s S,
    #[non_sensitive]
    context: Context<'static>,
}

impl<'s, S: OrderScheme + ?Sized> OrderContext<'s, S> {
    /// The space of `target` values under this context.
    ///
    /// Compiles only for a target the scheme [`Supports`].
    pub fn target<T: Target>(&self, target: T) -> OrderSpace<'s, S, T>
    where
        S: Supports<T> + Supports<OrderTarget>,
    {
        OrderSpace::new(self.scheme, target, &self.context)
    }

    /// Encrypt a value as the target its Rust type is, under this context.
    ///
    /// # Errors
    ///
    /// The scheme's own failure, and nothing else: the value always fits.
    pub fn encrypt<V>(&self, value: V) -> Result<OrderTerm<S::Term, V::Target>, S::Error>
    where
        V: OwnTarget + FitsIn<V::Target>,
        S: Supports<V::Target> + Supports<OrderTarget>,
    {
        self.target(V::Target::default()).encrypt(value)
    }

    /// Encrypt a value as the target its Rust type is, checking it while
    /// the program runs, under this context.
    ///
    /// # Errors
    ///
    /// As [`OrderSpace::encrypt_checked`].
    #[allow(clippy::type_complexity)]
    pub fn encrypt_checked<V: OwnTarget>(
        &self,
        value: V,
    ) -> Result<OrderTerm<S::Term, V::Target>, OrderError<S::Error>>
    where
        S: Supports<V::Target> + Supports<OrderTarget>,
    {
        self.target(V::Target::default()).encrypt_checked(value)
    }
}

/// One space of an order index on a scheme: the set of terms that compare
/// with each other, under one scheme, key, target and context. It holds
/// the target, the salt its terms are bound under, fixed when it is made
/// so every term of it agrees, and what the scheme derives under that
/// salt ([`OrderScheme::Space`]), derived once for every term of the
/// space. From [`OrderEncrypt::target`] or [`OrderContext::target`].
/// `Debug` shows the target and masks the scheme, whose key it holds,
/// the salt and what was derived.
///
/// The scheme opens the space when its first value is encrypted, or when
/// [`open`](Self::open) is called, so making one cannot fail and a chain
/// never needs a `?` before its value. If the scheme fails to open, every
/// encryption reports it and the next tries again. A one-shot chain
/// (`scheme.encrypt(v)`, `scheme.target(I32).encrypt(v)`) makes a space
/// per call and so opens the scheme per value; hold the space to derive
/// once for many values.
///
/// `T` is the target: a marker from [`target`](crate::target), whose
/// values the compiler checks through [`encrypt`](Self::encrypt), or
/// [`OrderTarget`], chosen while the program runs, whose values
/// [`encrypt_checked`](Self::encrypt_checked) checks then.
///
/// A space holds a reference to the scheme and the scheme's
/// [`Space`](OrderScheme::Space), so it is `Send` when the scheme is
/// `Sync` and its `Space` is `Send`, and `Sync` when its `Space` is `Sync`
/// too. A space of a scheme that keeps a random number generator behind
/// a `RefCell` is opened per thread.
#[derive(OpaqueDebug)]
pub struct OrderSpace<'s, S: OrderScheme + ?Sized, T: Target = OrderTarget> {
    scheme: &'s S,
    #[non_sensitive]
    target: T,
    salt: Context<'static>,
    /// What the scheme derived under the salt, once it has.
    opened: OnceLock<S::Space>,
}

/// `OrderSpace` under a target chosen while the program runs, as the 0.6
/// API named it.
#[deprecated(since = "0.7.0", note = "use `OrderSpace<'s, S, OrderTarget>`")]
pub type OrderColumn<'s, S> = OrderSpace<'s, S, OrderTarget>;

impl<'s, S: Supports<T> + Supports<OrderTarget> + ?Sized, T: Target> OrderSpace<'s, S, T> {
    fn new(scheme: &'s S, target: T, context: &Context<'_>) -> Self {
        // A marker impl vouches for its target; the runtime list must
        // agree, or a space under the marker would hand the scheme a
        // plaintext it cannot take. `supports_targets!` writes both from
        // one list; this catches a pair written by hand that disagree.
        debug_assert!(
            !<S as Supports<T>>::supports(target)
                || <S as Supports<OrderTarget>>::supports(target.runtime()),
            "{} implements Supports<{:?}> but refuses it at runtime",
            S::NAME,
            target.runtime()
        );
        Self {
            scheme,
            target,
            salt: salt(S::NAME, target.runtime(), context),
            opened: OnceLock::new(),
        }
    }

    /// Open the space now rather than at its first value: have the scheme
    /// derive what it keeps for the space under the salt. Encrypting does
    /// this when it has not been done; call it to hear about a scheme
    /// that cannot open before the first value, or to pay for the
    /// derivation up front.
    ///
    /// # Errors
    ///
    /// The scheme's own failure, from [`OrderScheme::open`]. Nothing is
    /// kept, so the next call tries again.
    pub fn open(&self) -> Result<(), S::Error> {
        self.opened().map(|_| ())
    }

    /// What the scheme keeps for this space, opening it if it has not
    /// been. Two threads may open it at once; one result is kept and the
    /// other dropped, and both are as good.
    fn opened(&self) -> Result<&S::Space, S::Error> {
        if let Some(opened) = self.opened.get() {
            return Ok(opened);
        }
        let opened = self.scheme.open(&self.salt)?;
        Ok(self.opened.get_or_init(|| opened))
    }

    /// This target under `context` instead: a new space, whose terms do
    /// not compare with this one's.
    pub fn context<'a, C: IntoContext<'a>>(&self, context: C) -> Self {
        Self::new(self.scheme, self.target, &context.into_context().encode())
    }

    /// The type every value of this space is encoded as.
    pub fn target(&self) -> OrderTarget {
        self.target.runtime()
    }

    /// The salt every term of this space is bound under. Not secret.
    pub fn salt(&self) -> &Context<'static> {
        &self.salt
    }

    /// Encrypt one scalar as this space's target, checking it while the
    /// program runs: an integer of any width it fits, a float, a string,
    /// bytes, or a typed value such as a date. Any [`Encrypt`] value,
    /// which is what an index layer holds when the target was chosen
    /// while the program ran.
    ///
    /// A scalar with no term is refused rather than skipped: a caller who
    /// asks for one term and gets none should hear about it.
    ///
    /// # Errors
    ///
    /// [`OrderError::Unsupported`] if the scheme does not take this
    /// target, [`OrderError::Term`] if the scalar has no term as the
    /// space's target, [`OrderError::NotScalar`] if the value is a
    /// container, [`OrderError::Source`] if the value could not be read,
    /// [`OrderError::Backend`] if the scheme failed.
    pub fn encrypt_checked<V: Encrypt>(
        &self,
        value: V,
    ) -> Result<OrderTerm<S::Term, T>, OrderError<S::Error>> {
        self.supported()?;
        let plaintext = value.visit(Scalar(self.target()))?;
        self.encrypt_plaintext(&plaintext)
    }

    /// Encrypt a plaintext [`order_terms`](crate::order_terms) collected
    /// from a whole value.
    ///
    /// # Errors
    ///
    /// [`OrderError::Term`] with [`NormalizeError::Mismatch`] if it was
    /// encoded as another target than this space's, else as
    /// [`encrypt_checked`](Self::encrypt_checked).
    pub fn encrypt_term(
        &self,
        plaintext: &OrderPlaintext,
    ) -> Result<OrderTerm<S::Term, T>, OrderError<S::Error>> {
        if plaintext.target() != self.target() {
            return Err(OrderError::Term(NormalizeError::Mismatch));
        }
        self.supported()?;
        self.encrypt_plaintext(plaintext)
    }

    /// A term the scheme already made in this space, read back from
    /// storage say, as the space's own: it then compares with the space's
    /// other terms. The caller vouches that it was made here; the space
    /// cannot tell.
    pub fn term(&self, raw: S::Term) -> OrderTerm<S::Term, T> {
        OrderTerm {
            raw,
            target: self.target,
        }
    }

    /// The order of two of this space's terms, as the order of the values
    /// they encrypt: [`OrderScheme::compare`]. A total order over the
    /// space's terms, so they sort by it.
    ///
    /// Both terms must be this space's. A term of a target named when the
    /// program is compiled cannot be another target's; a term of one
    /// chosen while it ran carries its target, and two of different
    /// targets, or of another target than this space's, are `None`. The
    /// scheme cannot always tell two spaces' terms apart otherwise, and
    /// may order them as noise. `None` where it can tell: a term not of
    /// this scheme, or two terms not made to compare.
    pub fn compare(
        &self,
        a: &OrderTerm<S::Term, T>,
        b: &OrderTerm<S::Term, T>,
    ) -> Option<Ordering> {
        let target = self.target();
        (a.target() == target && b.target() == target)
            .then(|| S::compare(&a.raw, &b.raw))
            .flatten()
    }

    /// Refuse a target the scheme does not take, by the scheme's runtime
    /// list. A marker's impl already vouched for its target when the
    /// space was opened; asking again costs a match.
    fn supported(&self) -> Result<(), OrderError<S::Error>> {
        if <S as Supports<OrderTarget>>::supports(self.target.runtime()) {
            Ok(())
        } else {
            Err(OrderError::Unsupported {
                scheme: S::NAME,
                domain: self.target().domain(),
            })
        }
    }

    fn encrypt_plaintext(
        &self,
        plaintext: &OrderPlaintext,
    ) -> Result<OrderTerm<S::Term, T>, OrderError<S::Error>> {
        self.encrypt_opened(plaintext).map_err(OrderError::Backend)
    }

    /// Open the space if it is not, then encrypt one plaintext of it.
    fn encrypt_opened(
        &self,
        plaintext: &OrderPlaintext,
    ) -> Result<OrderTerm<S::Term, T>, S::Error> {
        let opened = self.opened()?;
        self.scheme
            .encrypt_plaintext(opened, plaintext)
            .map(|raw| self.term(raw))
    }
}

impl<S: Supports<T> + Supports<OrderTarget> + ?Sized, T: StaticTarget> OrderSpace<'_, S, T> {
    /// Encrypt a value that always fits this space's target, as the
    /// [`FitsIn`] table says: an `i16` into an `I32` space, an `f32` into
    /// an `F64` one. The compiler refuses a value that might not fit, and
    /// names [`encrypt_checked`](Self::encrypt_checked) for it.
    ///
    /// # Errors
    ///
    /// The scheme's own failure, and nothing else: the value always fits,
    /// and the scheme [`Supports`] the target. A scheme whose `Error` is
    /// [`Infallible`](core::convert::Infallible) cannot fail at all.
    pub fn encrypt<V: FitsIn<T>>(&self, value: V) -> Result<OrderTerm<S::Term, T>, S::Error> {
        let plaintext = match value.visit(Scalar(T::TARGET)) {
            Ok(plaintext) => plaintext,
            // `FitsIn` is a sealed table of conversions the encoding never
            // refuses, and this crate's tests encrypt every row at its
            // extremes, so no value reaches here.
            Err(refused) => unreachable!("a `FitsIn` value was refused: {refused}"),
        };
        self.encrypt_opened(&plaintext)
    }
}

/// One term of an order space: the scheme's term, labelled with the target
/// it was made under.
///
/// Under a marker from [`target`](crate::target) the label is a zero-sized
/// type, so two terms of different targets cannot meet in
/// [`OrderSpace::compare`]: that does not compile. Under an
/// [`OrderTarget`] the label is stored, and two of different targets
/// compare as `None` instead of as noise. Storage reads the scheme's bytes
/// through `AsRef<[u8]>`, and [`raw`](Self::raw) is the scheme's term
/// itself.
///
/// `==` compares the stored term, byte for byte, not the value: the order
/// of two values is [`OrderSpace::compare`], and a randomised scheme
/// (block ORE carries a nonce) gives one value many terms, which compare
/// `Equal` and are not `==`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderTerm<R, T: Target> {
    raw: R,
    target: T,
}

impl<R, T: Target> OrderTerm<R, T> {
    /// The target the term was made under.
    pub fn target(&self) -> OrderTarget {
        self.target.runtime()
    }

    /// The scheme's own term.
    pub fn raw(&self) -> &R {
        &self.raw
    }

    /// The scheme's own term, unlabelled.
    pub fn into_raw(self) -> R {
        self.raw
    }
}

impl<R: AsRef<[u8]>, T: Target> OrderTerm<R, T> {
    /// The stored bytes: the scheme's term's.
    pub fn as_bytes(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl<R: AsRef<[u8]>, T: Target> AsRef<[u8]> for OrderTerm<R, T> {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

/// A scheme keyed from secret bytes, as
/// [`PrfKeyInit`](https://docs.rs/vitaminc-prf) keys a PRF, so an index
/// layer can construct any scheme the same way.
pub trait OrderKeyInit: OrderScheme + Sized {
    /// The scheme's full-strength key, a protected array.
    type Key: Controlled;
    /// Why key material of a length only known at runtime was refused.
    type KeyError: core::error::Error + Send + Sync + 'static;

    /// Key the scheme with a full-strength key. Cannot fail: the type
    /// carries the length.
    fn new(key: Self::Key) -> Self;

    /// Key the scheme with material whose length is only known at runtime,
    /// such as a KMS response.
    ///
    /// # Errors
    ///
    /// [`KeyError`](OrderKeyInit::KeyError) if the material is unfit, a
    /// short key say. Accepting it would produce terms anyone can order.
    fn try_from_bytes(key: Protected<Vec<u8>>) -> Result<Self, Self::KeyError>;
}

/// The sink one scalar is walked into: it encodes the scalar as its
/// target with [`order`] and refuses a container.
#[derive(Clone, Copy)]
struct Scalar(OrderTarget);

/// How one scalar fails to become a plaintext.
#[derive(Debug, thiserror::Error)]
enum ScalarError {
    #[error(transparent)]
    Term(NormalizeError),
    #[error("not a scalar")]
    NotScalar,
    #[error(transparent)]
    Source(SourceError),
}

impl plaintext::Error for ScalarError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl<E> From<ScalarError> for OrderError<E> {
    fn from(error: ScalarError) -> Self {
        match error {
            ScalarError::Term(e) => Self::Term(e),
            ScalarError::NotScalar => Self::NotScalar,
            ScalarError::Source(e) => Self::Source(e),
        }
    }
}

impl Sink for Scalar {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Seq = Never;
    type Map = Never;

    fn scalar(
        self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<OrderPlaintext, ScalarError> {
        order(self.0, ty, value).map_err(ScalarError::Term)
    }

    fn seq(self, _: Option<usize>) -> Result<Never, ScalarError> {
        Err(ScalarError::NotScalar)
    }

    fn map(self, _: Option<usize>) -> Result<Never, ScalarError> {
        Err(ScalarError::NotScalar)
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<OrderPlaintext, ScalarError> {
        Err(ScalarError::NotScalar)
    }
}

/// The container sink [`Scalar`] never hands out. Uninhabited, so it
/// cannot be built.
enum Never {}

impl SeqSink for Never {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Element<'s>
        = Scalar
    where
        Self: 's;

    fn element(&mut self) -> Result<Scalar, ScalarError> {
        match *self {}
    }

    fn end(self) -> Result<OrderPlaintext, ScalarError> {
        match self {}
    }
}

impl MapSink for Never {
    type Ok = OrderPlaintext;
    type Error = ScalarError;
    type Entry<'s>
        = Scalar
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<Scalar, ScalarError> {
        match *self {}
    }

    fn end(self) -> Result<OrderPlaintext, ScalarError> {
        match self {}
    }
}

impl fmt::Display for OrderPlaintext {
    /// The domain only: never the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.domain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain;
    use vitaminc_aead::Int;

    #[test]
    fn every_target_has_the_width_its_encoding_has() {
        for target in OrderTarget::ALL {
            let variable = matches!(target, OrderTarget::Text | OrderTarget::Bytes);
            assert_eq!(target.width().is_none(), variable, "{target:?}");
        }
        let p = order(OrderTarget::I32, None, Physical::Int(Int::I8(1))).expect("term");
        assert_eq!(p.width(), Some(4));
        assert_eq!(p.bytes().risky_ref().len(), 4);
        assert_eq!(p.target(), OrderTarget::I32);
        assert_eq!(
            order(OrderTarget::Text, None, Physical::Text("a"))
                .expect("term")
                .width(),
            None
        );
    }

    #[test]
    fn the_salt_binds_label_scheme_domain_and_context() {
        let context = ("tenant", 1u64).into_context().encode();
        let salted = salt("mock", OrderTarget::I8, &context);
        assert_eq!(
            salted,
            Context::pae(&[
                b"vitaminc/ore/v1",
                b"mock",
                domain::INT8.as_bytes(),
                context.as_bytes()
            ])
        );
        assert_ne!(salted, salt("other", OrderTarget::I8, &context));
        assert_ne!(salted, salt("mock", OrderTarget::U8, &context));
        assert_ne!(
            salted,
            salt(
                "mock",
                OrderTarget::I8,
                &("tenant", 2u64).into_context().encode()
            )
        );
    }

    #[test]
    fn debug_and_display_show_the_domain_and_mask_the_bytes() {
        let p = order(OrderTarget::Text, None, Physical::Text("secret")).expect("term");
        let shown = format!("{p:?}");
        assert!(shown.contains("Text") && shown.contains("***"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(p.to_string(), domain::TEXT);
    }

    #[test]
    fn errors_say_what_failed_without_plaintext() {
        type E = OrderError<&'static str>;
        assert_eq!(
            E::Term(NormalizeError::NoDomain).to_string(),
            "no order term: no domain for this kind of value"
        );
        assert_eq!(
            E::Term(NormalizeError::Mismatch).to_string(),
            "no order term: the value is not of the kind the index declares"
        );
        assert_eq!(
            E::Term(NormalizeError::OutOfRange).to_string(),
            "no order term: the value does not fit the type the index declares"
        );
        assert_eq!(
            E::NotScalar.to_string(),
            "a container has no single order term; walk it for one per scalar"
        );
        assert_eq!(
            E::Source(SourceError::msg("getter threw")).to_string(),
            "the value could not be read: getter threw"
        );
        assert_eq!(
            E::Unsupported {
                scheme: "block-ore",
                domain: domain::TEXT
            }
            .to_string(),
            "block-ore has no order term for vitaminc/ore/value/text-folded/unicode-16/v1"
        );
        assert_eq!(
            E::Backend("down").to_string(),
            "the order scheme failed: down"
        );
        let from: E = NormalizeError::Invalid.into();
        assert!(matches!(from, E::Term(NormalizeError::Invalid)));
    }

    #[test]
    fn the_scalar_sink_encodes_one_scalar_as_its_target_and_refuses_a_container() {
        let p = 7i16.visit(Scalar(OrderTarget::I64)).expect("scalar");
        assert_eq!(p.domain(), domain::INT64);
        assert!(matches!(
            vec![1u16, 2].visit(Scalar(OrderTarget::U16)),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            std::collections::BTreeMap::from([("k", 1u16)]).visit(Scalar(OrderTarget::U16)),
            Err(ScalarError::NotScalar)
        ));
        assert!(matches!(
            true.visit(Scalar(OrderTarget::U8)),
            Err(ScalarError::Term(NormalizeError::NoDomain))
        ));
    }
}
