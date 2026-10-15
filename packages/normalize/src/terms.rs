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
/// [`source_error`](TermsError::source_error) is the error as it arrived.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TermsError(SourceError);

impl TermsError {
    /// The scalar [`Terms`] refused, or `None` if the source failed on its
    /// own.
    pub fn term(&self) -> Option<&TermError> {
        self.0.inner().downcast_ref()
    }

    /// The failure as the walk reported it: what [`Terms`] refused, or the
    /// source's own error.
    pub fn source_error(&self) -> &SourceError {
        &self.0
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
///
/// # Cost
///
/// A path costs nothing until a term is pushed or a refusal is built. Each
/// child sink holds a link to its container's place and its own index, or
/// the position of its key in one buffer of the keys on the path being
/// walked, which the whole walk shares and reuses. So the walk allocates
/// that buffer, as long as the keys on the longest path, and otherwise
/// only what each pushed term needs.
pub struct Terms<'t, E> {
    out: &'t mut Vec<Term>,
    keys: Keys<'t>,
    at: Place<'t>,
    _error: PhantomData<E>,
}

/// The map keys on the path being walked, end to end. The root owns the
/// buffer and every sink below it borrows it. A container truncates it
/// back to where its own keys begin before each child, so it holds only
/// the keys of the current path.
enum Keys<'t> {
    Own(String),
    Lent(&'t mut String),
}

impl Keys<'_> {
    fn get(&mut self) -> &mut String {
        match self {
            Keys::Own(keys) => keys,
            Keys::Lent(keys) => keys,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Keys::Own(keys) => keys,
            Keys::Lent(keys) => keys,
        }
    }
}

/// Where a node sits: a link to its container's place and its own step.
/// A key is named by its position in [`Keys`].
#[derive(Clone, Copy)]
enum Place<'t> {
    Root,
    Element {
        parent: &'t Place<'t>,
        index: usize,
    },
    Entry {
        parent: &'t Place<'t>,
        key: (usize, usize),
    },
}

impl Place<'_> {
    /// Append the steps from the root to this node, reading keys from
    /// `keys`.
    fn locate(&self, keys: &str, steps: &mut Vec<Step>) {
        match *self {
            Place::Root => {}
            Place::Element { parent, index } => {
                parent.locate(keys, steps);
                steps.push(Step::Index(index));
            }
            Place::Entry {
                parent,
                key: (start, end),
            } => {
                parent.locate(keys, steps);
                steps.extend(keys.get(start..end).map(|key| Step::Key(key.to_owned())));
            }
        }
    }

    /// The path from the root to this node.
    fn path(&self, keys: &str) -> Path {
        let mut steps = Vec::new();
        self.locate(keys, &mut steps);
        Path::new(steps)
    }
}

impl<'t, E> Terms<'t, E> {
    /// A sink that appends to `out`.
    pub fn new(out: &'t mut Vec<Term>) -> Self {
        Self {
            out,
            keys: Keys::Own(String::new()),
            at: Place::Root,
            _error: PhantomData,
        }
    }

    fn path(&self) -> Path {
        self.at.path(self.keys.as_str())
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
                let path = self.path();
                self.out.push(Term { path, normalized });
                Ok(())
            }
            // No domain for the kind: nothing to index, carry on. No domain
            // for a logical type: refuse, see the type's docs.
            Err(NormalizeError::NoDomain) if matches!(ty, None | Some(Logical::Undefined)) => {
                Ok(())
            }
            Err(error) => Err(E::source(SourceError::new(TermError {
                path: self.path(),
                error,
            }))),
        }
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, E> {
        Ok(TermsSeq {
            mark: self.keys.as_str().len(),
            out: self.out,
            keys: self.keys,
            at: self.at,
            next: 0,
            _error: PhantomData,
        })
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, E> {
        Ok(TermsMap {
            mark: self.keys.as_str().len(),
            out: self.out,
            keys: self.keys,
            at: self.at,
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
    keys: Keys<'t>,
    /// Where this sequence's own keys would begin: the length of `keys`
    /// at its start.
    mark: usize,
    at: Place<'t>,
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
        let keys = self.keys.get();
        keys.truncate(self.mark);
        let index = self.next;
        self.next += 1;
        Ok(Terms {
            out: self.out,
            keys: Keys::Lent(keys),
            at: Place::Element {
                parent: &self.at,
                index,
            },
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
    keys: Keys<'t>,
    /// Where this map's keys begin in `keys`: its length at the map's
    /// start. Each entry's key replaces the last one there.
    mark: usize,
    at: Place<'t>,
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
        let keys = self.keys.get();
        keys.truncate(self.mark);
        keys.push_str(key);
        let key = (self.mark, keys.len());
        Ok(Terms {
            out: self.out,
            keys: Keys::Lent(keys),
            at: Place::Entry {
                parent: &self.at,
                key,
            },
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
