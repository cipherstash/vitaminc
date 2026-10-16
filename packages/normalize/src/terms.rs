//! Equality terms as a sink, and encryption that produces them in the
//! same walk.
//!
//! [`Terms`] is a [`Sink`] that produces one [`Term`] per scalar that has
//! an equality domain. It runs beside encryption as `Tee(EncryptSink,
//! Terms)`, so a caller holds every term before any cipher is called and,
//! with an async cipher, before the first await. [`terms`] runs it alone,
//! and then it refuses what encryption would refuse.
//!
//! The sink does the walking and the [`Normalize`] it is given does the
//! encoding, so an index of another kind (an order index, whose bytes
//! differ from an equality term's) collects its terms through the same
//! sink with a normalizer of its own, through [`Terms::by`] and
//! [`terms_by`].

use core::future::Future;
use core::marker::PhantomData;

use vitaminc_aead::plaintext::{Error, Path, Step};
use vitaminc_aead::seal::{seal_all, seal_all_async, AsyncCipher, Cipher};
use vitaminc_aead::shape::{self, Locate, MapRules, SeqRules, Settle};
use vitaminc_aead::{
    Encrypt, EncryptError, EncryptSink, IntoAad, Logical, MapSink, Node, Pending, Physical,
    Refusal, SeqSink, Sink, SourceError, Tee,
};

use vitaminc_protected::OpaqueDebug;

use crate::scalar::{normalize, NormalizeError, Normalized};

/// How [`Terms`] turns one scalar into a term.
///
/// [`Equality`] is the normalizer this crate is about. An index of another
/// kind supplies its own, with a term type of its own (an order index
/// seals its term so only a scheme can read it) and the same outcome
/// contract: a scalar whose kind has no term under this index (a null, a
/// boolean) returns [`NormalizeError::NoDomain`], and [`Terms`] skips it
/// when it has no logical type; a scalar whose logical type has no term
/// returns the same error and stops the walk; any other error stops the
/// walk too.
///
/// A normalizer is copied into every child sink of a walk, so it is
/// `Copy`: it carries settings, such as the type an index declares, but
/// no state that a walk changes.
pub trait Normalize: Copy {
    /// What one scalar becomes.
    type Term;

    /// The kind of index the terms are for, as a refusal names it:
    /// `"equality"` for [`Equality`], so a scalar it cannot normalize is
    /// reported as having no equality term.
    const INDEX: &'static str;

    /// The term for one scalar, or why it has none.
    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<Self::Term, NormalizeError>;
}

/// The equality normalizer: [`normalize`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Equality;

impl Normalize for Equality {
    type Term = Normalized;

    const INDEX: &'static str = "equality";

    fn normalize(
        &self,
        ty: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<Normalized, NormalizeError> {
        normalize(ty, value)
    }
}

/// One term: where the scalar sits in the value, and what the normalizer
/// made of it. An equality term, a [`Normalized`], unless [`Terms::by`]
/// was given another normalizer.
///
/// `Debug` shows the path's shape, with its map keys masked as [`Step`]
/// masks them, and masks the term.
#[derive(OpaqueDebug)]
pub struct Term<T = Normalized> {
    /// The path from the root, empty for a scalar at the root.
    #[non_sensitive]
    pub path: Path,
    /// The term itself: for equality, the frozen domain label and the
    /// normalized bytes.
    pub normalized: T,
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
#[error("no {index} term: {error}")]
pub struct TermError {
    #[non_sensitive]
    index: &'static str,
    #[non_sensitive]
    path: Path,
    #[non_sensitive]
    #[source]
    error: NormalizeError,
}

impl TermError {
    /// The kind of index the scalar has no term for: the normalizer's
    /// [`Normalize::INDEX`].
    pub fn index(&self) -> &'static str {
        self.index
    }

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
/// every failure arrives as a [`SourceError`]. [`term`](TermsError::term)
/// recovers a [`TermError`] from it, the same downcast a caller makes on
/// [`EncryptError::Source`] when `Terms` runs beside encryption, and
/// [`refusal`](TermsError::refusal) a value refused for its shape, which
/// encryption reports as [`EncryptError::Shape`].
/// [`source_error`](TermsError::source_error) is the error as it arrived.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TermsError(SourceError);

impl TermsError {
    /// The scalar [`Terms`] refused, or `None` if the source failed on its
    /// own or the value was refused for its shape.
    pub fn term(&self) -> Option<&TermError> {
        self.0.inner().downcast_ref()
    }

    /// The value refused for its shape, as encryption would refuse it, or
    /// `None` if it was refused for another reason.
    pub fn refusal(&self) -> Option<&Refusal> {
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
/// [`TermsError`]. Generic too over the [`Normalize`] that encodes each
/// scalar, [`Equality`] unless [`by`](Terms::by) is given another, so an
/// index of another kind collects its terms through this same walk.
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
/// # Only what can be encrypted
///
/// A `Terms` refuses every value [`EncryptSink`] refuses, for the same
/// [`Unencryptable`](vitaminc_aead::Unencryptable) reason and at the same path, so an index never holds
/// terms for a value that cannot be stored. It keeps the
/// [`shape`](vitaminc_aead::shape) rules through the code `EncryptSink`
/// keeps them with: nothing deeper than the transport's depth limit, every
/// scalar valid for its logical type, every passthrough subtree framable,
/// no map key given twice, no child sink dropped without a value, and
/// something sealed in every container with children. The last rule is
/// about sealing, and this walk seals nothing, but a value that breaks it
/// cannot be encrypted, so it is refused here too. A passthrough is framed
/// as encryption frames it, to check that it can be, and the frame is
/// dropped.
///
/// So [`terms`] accepts a value exactly when [`encrypt_with_terms`] does
/// with a cipher that does not fail, and refuses it for the same reason at
/// the same path. [`plan_with_terms`], and the encrypting functions built
/// on it, pair `EncryptSink` with a `Terms` that leaves the shape rules to
/// it, so they are kept once.
///
/// # Errors
///
/// The walk stops with `E::source(SourceError::new(error))`, where `error`
/// is one of:
///
/// - a [`Refusal`]: the value breaks a shape rule, as above. A scalar not
///   valid for its logical type is refused this way, as
///   [`Unencryptable::InvalidValue`](vitaminc_aead::Unencryptable::InvalidValue), before it is normalized. Through
///   [`terms`] it is [`TermsError::refusal`]. Beside `EncryptSink`, which
///   refuses it first, it is [`EncryptError::Shape`].
/// - a [`TermError`] holding the scalar's path and the
///   [`NormalizeError`]: the scalar's logical type has no domain
///   (`NoDomain`), or its text holds a code point unassigned in Unicode 16
///   (`UnassignedCodePoint`). Beside [`EncryptSink`] that arrives as
///   [`EncryptError::Source`], and
///   `source.inner().downcast_ref::<TermError>()` recovers it. Alone,
///   through [`terms`], it is [`TermsError::term`]. Either way the
///   [`NormalizeError`] is on the `source()` chain.
///
/// # Cost
///
/// A path costs nothing until a term is pushed or a refusal is built. Each
/// child sink holds a link to its container's place and its own index, or
/// the position of its key in one buffer of the keys on the path being
/// walked, which the whole walk shares and reuses. So the walk allocates
/// that buffer, as long as the keys on the longest path, and otherwise
/// only what each pushed term needs.
///
/// The shape rules cost what they cost encryption: a map keeps one copy
/// of each of its keys until it ends, which is what checking for a repeat
/// exactly takes, and a passthrough is framed. Beside `EncryptSink`,
/// through [`plan_with_terms`], none of that is paid twice. A caller that
/// tees `Terms::new` beside `EncryptSink` itself has both keep the rules.
pub struct Terms<'t, E, N: Normalize = Equality> {
    out: &'t mut Vec<Term<N::Term>>,
    keys: Keys<'t>,
    at: Place<'t>,
    /// `None` beside an [`EncryptSink`] that keeps the rules itself.
    rules: Option<NodeRules<'t>>,
    by: N,
    _error: PhantomData<E>,
}

/// The shape rules one node keeps: how deep it sits, and its hold on its
/// container's rules, which it settles when it ends. The root has no
/// container.
struct NodeRules<'t> {
    depth: usize,
    settle: Option<Settle<'t>>,
}

impl NodeRules<'_> {
    /// The node put a sealed node: a scalar, or a container.
    fn sealed(self) {
        if let Some(settle) = self.settle {
            settle.sealed();
        }
    }
}

/// A container's shape rules, `R`, with the rules of the node it is.
struct Held<'t, R> {
    node: NodeRules<'t>,
    rules: R,
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

/// A place with the keys it names: what the shape rules locate a refusal
/// with.
struct At<'a> {
    place: &'a Place<'a>,
    keys: &'a str,
}

impl Locate for At<'_> {
    fn locate(&self, steps: &mut Vec<Step>) {
        self.place.locate(self.keys, steps);
    }
}

/// A shape refusal, reported the only way a sink generic over its error
/// can report anything.
fn refused<E: Error>(refusal: Refusal) -> E {
    E::source(SourceError::new(refusal))
}

impl<'t, E> Terms<'t, E> {
    /// A sink that appends equality terms to `out` and keeps the shape
    /// rules itself.
    pub fn new(out: &'t mut Vec<Term>) -> Self {
        Self::by(Equality, out)
    }

    /// A sink that appends to `out` and leaves the shape rules to the
    /// [`EncryptSink`] it is teed beside, which refuses first.
    fn beside_encryption(out: &'t mut Vec<Term>) -> Self {
        Self {
            rules: None,
            ..Self::new(out)
        }
    }
}

impl<'t, E, N: Normalize> Terms<'t, E, N> {
    /// A sink that appends the terms `by` makes to `out` and keeps the
    /// shape rules itself.
    ///
    /// The normalizer is copied into every child sink, which is why
    /// [`Normalize`] requires `Copy`.
    pub fn by(by: N, out: &'t mut Vec<Term<N::Term>>) -> Self {
        Self {
            out,
            keys: Keys::Own(String::new()),
            at: Place::Root,
            rules: Some(NodeRules {
                depth: 0,
                settle: None,
            }),
            by,
            _error: PhantomData,
        }
    }

    fn at(&self) -> At<'_> {
        At {
            place: &self.at,
            keys: self.keys.as_str(),
        }
    }
}

impl<'t, E: Error, N: Normalize> Sink for Terms<'t, E, N> {
    type Ok = ();
    type Error = E;
    type Seq = TermsSeq<'t, E, N>;
    type Map = TermsMap<'t, E, N>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), E> {
        if let Some(rules) = &self.rules {
            shape::scalar(rules.depth, ty, &value, &self.at()).map_err(refused)?;
        }
        match self.by.normalize(ty, value) {
            Ok(normalized) => {
                let path = self.at.path(self.keys.as_str());
                self.out.push(Term { path, normalized });
            }
            // No domain for the kind: nothing to index, carry on. No domain
            // for a logical type: refuse, see the type's docs.
            Err(NormalizeError::NoDomain) if matches!(ty, None | Some(Logical::Undefined)) => {}
            Err(error) => {
                return Err(E::source(SourceError::new(TermError {
                    index: N::INDEX,
                    path: self.at.path(self.keys.as_str()),
                    error,
                })))
            }
        }
        if let Some(rules) = self.rules {
            rules.sealed();
        }
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, E> {
        let rules = match self.rules {
            Some(node) => {
                shape::container(
                    node.depth,
                    &At {
                        place: &self.at,
                        keys: self.keys.as_str(),
                    },
                )
                .map_err(refused)?;
                Some(Held {
                    node,
                    rules: SeqRules::new(),
                })
            }
            None => None,
        };
        Ok(TermsSeq {
            mark: self.keys.as_str().len(),
            out: self.out,
            keys: self.keys,
            at: self.at,
            next: 0,
            rules,
            by: self.by,
            _error: PhantomData,
        })
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, E> {
        let rules = match self.rules {
            Some(node) => {
                shape::container(
                    node.depth,
                    &At {
                        place: &self.at,
                        keys: self.keys.as_str(),
                    },
                )
                .map_err(refused)?;
                Some(Held {
                    node,
                    rules: MapRules::new(),
                })
            }
            None => None,
        };
        Ok(TermsMap {
            mark: self.keys.as_str().len(),
            out: self.out,
            keys: self.keys,
            at: self.at,
            rules,
            by: self.by,
            _error: PhantomData,
        })
    }

    /// No terms. Keeping the shape rules, the subtree is framed, as
    /// encryption frames it, and the frame dropped.
    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), E> {
        if let Some(rules) = self.rules {
            let at = At {
                place: &self.at,
                keys: self.keys.as_str(),
            };
            shape::frame_passthrough(value, rules.depth, &at, refused)?;
            if let Some(settle) = rules.settle {
                settle.passthrough();
            }
        }
        Ok(())
    }
}

/// The sequence side of [`Terms`]: each element's path is the sequence's
/// plus its index.
pub struct TermsSeq<'t, E, N: Normalize = Equality> {
    out: &'t mut Vec<Term<N::Term>>,
    keys: Keys<'t>,
    /// Where this sequence's own keys would begin: the length of `keys`
    /// at its start.
    mark: usize,
    at: Place<'t>,
    next: usize,
    rules: Option<Held<'t, SeqRules>>,
    by: N,
    _error: PhantomData<E>,
}

impl<E: Error, N: Normalize> SeqSink for TermsSeq<'_, E, N> {
    type Ok = ();
    type Error = E;
    type Element<'s>
        = Terms<'s, E, N>
    where
        Self: 's;

    fn element(&mut self) -> Result<Terms<'_, E, N>, E> {
        let TermsSeq {
            out,
            keys,
            mark,
            at,
            next,
            rules,
            by,
            ..
        } = self;
        let keys = keys.get();
        let rules = match rules {
            Some(held) => Some(NodeRules {
                depth: held.node.depth + 1,
                settle: Some(
                    held.rules
                        .element(&At { place: at, keys })
                        .map_err(refused)?,
                ),
            }),
            None => None,
        };
        keys.truncate(*mark);
        let index = *next;
        *next += 1;
        Ok(Terms {
            out,
            keys: Keys::Lent(keys),
            at: Place::Element { parent: at, index },
            rules,
            by: *by,
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<(), E> {
        if let Some(held) = self.rules {
            let at = At {
                place: &self.at,
                keys: self.keys.as_str(),
            };
            held.rules.end(&at).map_err(refused)?;
            held.node.sealed();
        }
        Ok(())
    }
}

/// The map side of [`Terms`]: each entry's path is the map's plus its
/// key.
pub struct TermsMap<'t, E, N: Normalize = Equality> {
    out: &'t mut Vec<Term<N::Term>>,
    keys: Keys<'t>,
    /// Where this map's keys begin in `keys`: its length at the map's
    /// start. Each entry's key replaces the last one there.
    mark: usize,
    at: Place<'t>,
    rules: Option<Held<'t, MapRules>>,
    by: N,
    _error: PhantomData<E>,
}

impl<E: Error, N: Normalize> MapSink for TermsMap<'_, E, N> {
    type Ok = ();
    type Error = E;
    type Entry<'s>
        = Terms<'s, E, N>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Terms<'_, E, N>, E> {
        let TermsMap {
            out,
            keys,
            mark,
            at,
            rules,
            by,
            ..
        } = self;
        let keys = keys.get();
        let rules = match rules {
            Some(held) => Some(NodeRules {
                depth: held.node.depth + 1,
                settle: Some(
                    held.rules
                        .entry(key, &At { place: at, keys })
                        .map_err(refused)?,
                ),
            }),
            None => None,
        };
        keys.truncate(*mark);
        keys.push_str(key);
        let key = (*mark, keys.len());
        Ok(Terms {
            out,
            keys: Keys::Lent(keys),
            at: Place::Entry { parent: at, key },
            rules,
            by: *by,
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<(), E> {
        if let Some(held) = self.rules {
            let at = At {
                place: &self.at,
                keys: self.keys.as_str(),
            };
            held.rules.end(&at).map_err(refused)?;
            held.node.sealed();
        }
        Ok(())
    }
}

/// Every equality term of `value`, in walk order, without encrypting it.
///
/// It refuses every value encryption refuses, for the same reason at the
/// same path (see [`Terms`]), so it never returns terms for a value that
/// cannot be stored.
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
///
/// // A uuid of three bytes cannot be encrypted, so it has no term either:
/// // `terms` refuses it as encryption does.
/// use vitaminc_aead::{Logical, Physical, Raw, Unencryptable};
/// let id = Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]));
/// let refused = terms(id).unwrap_err();
/// let refusal = refused.refusal().expect("refused for its shape");
/// assert_eq!(refusal.reason(), Unencryptable::InvalidValue);
/// # Ok::<(), vitaminc_normalize::TermsError>(())
/// ```
///
/// # Errors
///
/// [`TermsError`]: what [`Terms`] refuses, a value encryption would refuse
/// included, or the source's own failure.
pub fn terms<P: Encrypt>(value: P) -> Result<Vec<Term>, TermsError> {
    terms_by(Equality, value)
}

/// Every term of `value` under the normalizer `by`, in walk order, without
/// encrypting it: [`terms`] for an index of another kind.
///
/// It refuses what [`terms`] refuses for the value's shape, and what `by`
/// refuses for a scalar, the way [`Terms`] describes.
///
/// # Errors
///
/// [`TermsError`]: what [`Terms`] refuses, a value encryption would refuse
/// included, or the source's own failure.
pub fn terms_by<N, P>(by: N, value: P) -> Result<Vec<Term<N::Term>>, TermsError>
where
    N: Normalize,
    P: Encrypt,
{
    let mut out = Vec::new();
    value.visit(Terms::by(by, &mut out))?;
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
    P: Encrypt,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let (planned, ()) = value.visit(Tee(
        EncryptSink::root(aad),
        Terms::beside_encryption(&mut terms),
    ))?;
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
    P: Encrypt,
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
    P: Encrypt,
    C: AsyncCipher,
    A: IntoAad<'a>,
{
    let planned = plan_with_terms(value, aad);
    async move {
        let (planned, terms) = planned?;
        Ok((seal_all_async(cipher, planned).await?, terms))
    }
}
