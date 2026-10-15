//! Equality terms as a sink, and encryption that produces them in the
//! same walk.
//!
//! [`Terms`] is a [`Sink`] that produces one [`Term`] per scalar that has
//! an equality domain. It runs beside encryption as `Tee(EncryptSink,
//! Terms)`, so a caller holds every term before any cipher is called and,
//! with an async cipher, before the first await. [`terms`] runs it alone.

use core::future::Future;
use core::marker::PhantomData;

use vitaminc_aead::plaintext::{Error, Path, Step};
use vitaminc_aead::seal::{seal_all, seal_all_async, AsyncCipher, Cipher};
use vitaminc_aead::{
    EncryptError, EncryptSink, IntoAad, Logical, MapSink, Node, Pending, Physical, Plaintext,
    SeqSink, Sink, SourceError, Tee,
};

use vitaminc_protected::OpaqueDebug;

use crate::scalar::{normalize, NormalizeError, Normalized};

/// One equality term: where the scalar sits in the value, and its
/// normalized bytes with their domain.
///
/// `Debug` shows the path's shape, with its map keys masked as [`Step`]
/// masks them, and masks the term.
#[derive(OpaqueDebug)]
pub struct Term {
    /// The path from the root, empty for a scalar at the root.
    #[non_sensitive]
    pub path: Path,
    /// The term itself: the frozen domain label and the normalized bytes.
    pub normalized: Normalized,
}

/// A scalar [`Terms`] refused: why, and where in the value.
///
/// This is the type to downcast a refusal to. Its
/// [`source`](core::error::Error::source) is the [`NormalizeError`], so a
/// reporter that walks the error chain reaches the reason too.
///
/// `Display` shows only the reason, because the path can hold map keys and
/// map keys can be user data. `Debug` shows the reason and the path's
/// shape, with every key masked. Read the path with
/// [`path`](TermError::path).
#[derive(Clone, OpaqueDebug, thiserror::Error)]
#[error("no equality term: {error}")]
pub struct TermError {
    #[non_sensitive]
    path: Path,
    #[non_sensitive]
    #[source]
    error: NormalizeError,
}

impl TermError {
    /// Where the refused scalar sits, from the root.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Why the scalar has no term.
    pub fn error(&self) -> NormalizeError {
        self.error
    }
}

/// What [`terms`] fails with: what [`Terms`] refuses, or the source's own
/// failure.
///
/// A source reports through [`Error::source`] whichever sink it feeds, so
/// both arrive as a [`SourceError`]. [`term`](TermsError::term) recovers a
/// [`TermError`] from it, the same downcast a caller makes on
/// [`EncryptError::Source`] when `Terms` runs beside encryption.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TermsError(pub SourceError);

impl TermsError {
    /// The scalar [`Terms`] refused, or `None` if the source failed on its
    /// own.
    pub fn term(&self) -> Option<&TermError> {
        self.0.inner().downcast_ref()
    }
}

impl Error for TermsError {
    fn source(error: SourceError) -> Self {
        Self(error)
    }
}

/// A sink that collects one [`Term`] per scalar with an equality domain,
/// in walk order.
///
/// Generic over its error type so it adopts its [`Tee`] partner's. To
/// collect terms without encrypting, call [`terms`], whose error type is
/// [`TermsError`].
///
/// A scalar whose *kind* has no domain (a null, a boolean, an `undefined`)
/// produces no term and does not stop the walk: an absent or unindexable
/// value is an ordinary thing to find in a document, and the caller has
/// the paths to see which fields were indexed. A scalar whose *logical
/// type* has no domain ([`Logical::Unknown`], or a type this crate does
/// not know) stops the walk instead: it came from a newer client and
/// means something, and encrypting it with no term and no error would
/// leave an index silently incomplete.
///
/// Passthrough subtrees travel in the clear and get no terms.
///
/// # Errors
///
/// The walk stops with `E::source(SourceError::new(error))`, where `error`
/// is a [`TermError`] holding the scalar's path and the
/// [`NormalizeError`]: the scalar's logical type has no domain
/// (`NoDomain`), its text holds a code point unassigned in Unicode 16
/// (`UnassignedCodePoint`), or it is not valid for its logical type
/// (`Invalid`). Beside [`EncryptSink`] that arrives as
/// [`EncryptError::Source`], and `source.inner().downcast_ref::<TermError>()`
/// recovers it. Alone, through [`terms`], it is [`TermsError::term`].
/// Either way the [`NormalizeError`] is on the `source()` chain.
pub struct Terms<'t, E> {
    out: &'t mut Vec<Term>,
    /// The path of the container this sink is a child of, borrowed from
    /// that container's sink, and the step from it to this value. Owned
    /// only when a term is pushed, so a child that produces none costs no
    /// allocation.
    parent: &'t [Step],
    step: Option<Step>,
    _error: PhantomData<E>,
}

impl<'t, E> Terms<'t, E> {
    /// A sink that appends to `out`.
    pub fn new(out: &'t mut Vec<Term>) -> Self {
        Self {
            out,
            parent: &[],
            step: None,
            _error: PhantomData,
        }
    }

    fn path(&self) -> Vec<Step> {
        let mut path = Vec::with_capacity(self.parent.len() + usize::from(self.step.is_some()));
        path.extend_from_slice(self.parent);
        path.extend(self.step.iter().cloned());
        path
    }
}

impl<'t, E: Error> Sink for Terms<'t, E> {
    type Ok = ();
    type Error = E;
    type Seq = TermsSeq<'t, E>;
    type Map = TermsMap<'t, E>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), E> {
        match normalize(ty, value) {
            Ok(normalized) => {
                let path = Path::new(self.path());
                self.out.push(Term { path, normalized });
                Ok(())
            }
            // No domain for the kind: nothing to index, carry on. No domain
            // for a logical type: refuse, see the type's docs.
            Err(NormalizeError::NoDomain) if matches!(ty, None | Some(Logical::Undefined)) => {
                Ok(())
            }
            Err(error) => Err(E::source(SourceError::new(TermError {
                path: Path::new(self.path()),
                error,
            }))),
        }
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, E> {
        Ok(TermsSeq {
            path: self.path(),
            out: self.out,
            next: 0,
            _error: PhantomData,
        })
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, E> {
        Ok(TermsMap {
            path: self.path(),
            out: self.out,
            _error: PhantomData,
        })
    }

    fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<(), E> {
        Ok(())
    }
}

/// The sequence side of [`Terms`]: each element's path is the sequence's
/// plus its index.
pub struct TermsSeq<'t, E> {
    out: &'t mut Vec<Term>,
    path: Vec<Step>,
    next: usize,
    _error: PhantomData<E>,
}

impl<E: Error> SeqSink for TermsSeq<'_, E> {
    type Ok = ();
    type Error = E;
    type Element<'s>
        = Terms<'s, E>
    where
        Self: 's;

    fn element(&mut self) -> Result<Terms<'_, E>, E> {
        let step = Step::Index(self.next);
        self.next += 1;
        Ok(Terms {
            out: self.out,
            parent: &self.path,
            step: Some(step),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<(), E> {
        Ok(())
    }
}

/// The map side of [`Terms`]: each entry's path is the map's plus its
/// key.
pub struct TermsMap<'t, E> {
    out: &'t mut Vec<Term>,
    path: Vec<Step>,
    _error: PhantomData<E>,
}

impl<E: Error> MapSink for TermsMap<'_, E> {
    type Ok = ();
    type Error = E;
    type Entry<'s>
        = Terms<'s, E>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Terms<'_, E>, E> {
        Ok(Terms {
            out: self.out,
            parent: &self.path,
            step: Some(Step::Key(key.to_owned())),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<(), E> {
        Ok(())
    }
}

/// Every equality term of `value`, in walk order, without encrypting it.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use vitaminc_normalize::{domain, terms, NormalizeError, Step};
///
/// let mut user = BTreeMap::new();
/// user.insert("name", "Ada");
/// let found = terms(&user)?;
/// assert_eq!(found[0].path.steps(), [Step::Key("name".into())]);
/// assert_eq!(found[0].normalized.domain, domain::TEXT);
///
/// // U+0378 is unassigned in Unicode 16, so the name has no term.
/// user.insert("name", "\u{378}");
/// let refused = terms(&user).unwrap_err();
/// let term = refused.term().expect("refused by Terms");
/// assert_eq!(term.error(), NormalizeError::UnassignedCodePoint);
/// assert_eq!(term.path().steps(), [Step::Key("name".into())]);
/// // The message names neither the field nor its value.
/// assert_eq!(
///     refused.to_string(),
///     "no equality term: text contains a code point unassigned in Unicode 16"
/// );
/// # Ok::<(), vitaminc_normalize::TermsError>(())
/// ```
///
/// # Errors
///
/// [`TermsError`]: what [`Terms`] refuses, or the source's own failure.
pub fn terms<P: Plaintext>(value: P) -> Result<Vec<Term>, TermsError> {
    let mut out = Vec::new();
    value.visit(Terms::new(&mut out))?;
    Ok(out)
}

/// A ciphertext tree and the terms of the value it was sealed from, in
/// walk order.
pub type WithTerms<L> = (Node<L>, Vec<Term>);

/// Walk `value` into the encrypting sink and the terms sink at once,
/// without sealing: the planned tree of pending leaves, and every term.
///
/// # Errors
///
/// Everything [`EncryptSink`] refuses, plus what [`Terms`] refuses, which
/// arrives as [`EncryptError::Source`] carrying a [`TermError`].
pub fn plan_with_terms<'a, P, E, A>(value: P, aad: A) -> Result<WithTerms<Pending>, EncryptError<E>>
where
    P: Plaintext,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let (planned, ()) = value.visit(Tee(EncryptSink::root(aad), Terms::new(&mut terms)))?;
    Ok((planned, terms))
}

/// Encrypt `value` and produce its equality terms in the same walk.
///
/// # Errors
///
/// As [`plan_with_terms`], then [`EncryptError::Cipher`] if the cipher
/// refuses a leaf.
pub fn encrypt_with_terms<'a, P, C, A>(
    value: P,
    cipher: &C,
    aad: A,
) -> Result<WithTerms<C::Leaf>, EncryptError<C::Error>>
where
    P: Plaintext,
    C: Cipher,
    A: IntoAad<'a>,
{
    let (planned, terms) = plan_with_terms(value, aad)?;
    Ok((seal_all(cipher, planned)?, terms))
}

/// Encrypt `value` through an async cipher and produce its equality terms
/// in the same walk. The walk, and so every term, is complete before the
/// future is returned, so the future holds only the planned leaves and is
/// `Send` even when the source is not.
///
/// # Errors
///
/// As [`encrypt_with_terms`]. A refusal during the walk is held in the
/// future and returned on its first poll.
pub fn encrypt_with_terms_async<'a, 'c, P, C, A>(
    value: P,
    cipher: &'c C,
    aad: A,
) -> impl Future<Output = Result<WithTerms<C::Leaf>, EncryptError<C::Error>>> + Send + 'c
where
    P: Plaintext,
    C: AsyncCipher,
    A: IntoAad<'a>,
{
    let planned = plan_with_terms(value, aad);
    async move {
        let (planned, terms) = planned?;
        Ok((seal_all_async(cipher, planned).await?, terms))
    }
}
