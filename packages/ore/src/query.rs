//! The query side of an order scheme: what a caller makes from the value
//! it is searching for, to compare against a space's stored terms.
//!
//! A block ORE scheme (Lewi-Wu) has two halves. The right half is what
//! a stored term needs to be compared against; the left half is what a
//! comparison needs from the other side, and a left half alone is a
//! **query**: smaller than a stored term, made from the value being
//! searched for, and enough to drive the comparison against every term
//! of the space. A scheme whose terms are their own queries, as the CLWW
//! schemes are, implements this with `Query = Term`.
//!
//! A caller makes one through the space, as it makes a term:
//! `space.encrypt_query(value)`, and compares it with
//! `space.compare_query(&query, &term)`. A query exists for that
//! comparison and is not persisted or logged; [`OrderQuery`] says why.

use core::cmp::Ordering;

use vitaminc_aead::Encrypt;
use vitaminc_normalize::NormalizeError;

use crate::scheme::{OrderError, OrderPlaintext, OrderScheme, OrderSpace, OrderTerm, Scalar};
use crate::target::{FitsIn, StaticTarget, Supports, Target};
use crate::OrderTarget;

/// An order scheme that makes queries: what a caller makes from the
/// value it is searching for, to compare against the space's stored
/// terms.
///
/// Implemented beside [`OrderScheme`] by a scheme that has a query side,
/// and trivially, with `Query = Term`, by one whose terms are their own
/// queries. A caller does not call it: it makes queries through
/// [`OrderSpace::encrypt_query`] and compares them through
/// [`OrderSpace::compare_query`], so a query is bound to the same salt
/// as the terms it is compared with.
///
/// A query exists for the comparison at hand, and should not be
/// persisted or logged. Held beside the stored terms, it orders every
/// one of them against the searched value, for whoever holds both. And
/// block ORE's queries are deterministic, one value in one space giving
/// one query, so `==` on two of its queries is equality of the values
/// searched for, and a log of queries is a log of what was searched.
pub trait OrderQuery: OrderScheme {
    /// What one query encrypts to. For a scheme whose terms are their own
    /// queries, [`Term`](OrderScheme::Term).
    type Query: AsRef<[u8]>;

    /// Encrypt a sealed plaintext of `space` as a query, with what
    /// [`open`](OrderScheme::open) made under the space's salt.
    ///
    /// The plaintext is of a target the scheme [`Supports`]: the space
    /// checks before calling. So the only failure is the scheme's own.
    ///
    /// # Errors
    ///
    /// The scheme's own failure.
    fn encrypt_query(
        &self,
        space: &Self::Space,
        plaintext: &OrderPlaintext,
    ) -> Result<Self::Query, Self::Error>;

    /// The order of the value `query` encrypts relative to the value
    /// `term` encrypts: `Less` when the queried value sorts before the
    /// stored one. Needs no key, as [`compare`](OrderScheme::compare)
    /// does not.
    ///
    /// `None` says the two cannot be compared: one is not this scheme's,
    /// or the two were not made to compare. The same contract as
    /// [`compare`](OrderScheme::compare): across spaces the noise is in
    /// the direction and never in equality.
    fn compare_query(query: &Self::Query, term: &Self::Term) -> Option<Ordering>;
}

/// One query of an order space: the scheme's query, labelled with the
/// target it was made under, as an [`OrderTerm`] is.
///
/// Under a marker from [`target`](crate::target) the label is a
/// zero-sized type, so a query of one target cannot meet a term of
/// another in [`OrderSpace::compare_query`]: that does not compile.
/// Under an [`OrderTarget`] the label is stored, and a query and a term
/// of different targets compare as `None` instead of as noise.
///
/// A query is not a term: it has its own type, so it cannot be compared
/// where a term is expected, and the compiler refuses
/// `space.compare(&query, &term)`. Its bytes are bytes, though, as a
/// term's are: [`as_bytes`](Self::as_bytes) and `AsRef<[u8]>` are there
/// so a caller can send the query to wherever the terms are, and nothing
/// stops a caller writing them into a term's place. Under block ORE a
/// query has no right half, so every later `compare` against those bytes
/// returns `None`; under a scheme whose `Query` is its `Term` the mistake
/// is invisible.
///
/// `==` compares the bytes. Whether that is equality of the values
/// searched for depends on the scheme: under block ORE, whose queries are
/// deterministic, it is. A query is for the comparison at hand and should
/// not be persisted or logged, as [`OrderQuery`] explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryTerm<R, T: Target> {
    raw: R,
    target: T,
}

impl<R, T: Target> QueryTerm<R, T> {
    /// The target the query was made under.
    pub fn target(&self) -> OrderTarget {
        self.target.runtime()
    }

    /// The scheme's own query.
    pub fn raw(&self) -> &R {
        &self.raw
    }

    /// The scheme's own query, unlabelled.
    pub fn into_raw(self) -> R {
        self.raw
    }
}

impl<R: AsRef<[u8]>, T: Target> QueryTerm<R, T> {
    /// The query's bytes: the scheme's query's.
    pub fn as_bytes(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl<R: AsRef<[u8]>, T: Target> AsRef<[u8]> for QueryTerm<R, T> {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_ref()
    }
}

impl<S: OrderQuery + Supports<T> + Supports<OrderTarget> + ?Sized, T: Target> OrderSpace<'_, S, T> {
    /// Encrypt one scalar as a query of this space's target, checking it
    /// while the program runs, as
    /// [`encrypt_checked`](Self::encrypt_checked) checks a term.
    ///
    /// The query is for the comparison at hand: held beside the stored
    /// terms it orders every one of them against the value, so it should
    /// not be persisted or logged (see [`OrderQuery`]).
    ///
    /// # Errors
    ///
    /// As [`encrypt_checked`](Self::encrypt_checked).
    pub fn encrypt_query_checked<V: Encrypt>(
        &self,
        value: V,
    ) -> Result<QueryTerm<S::Query, T>, OrderError<S::Error>> {
        self.supported()?;
        let plaintext = value.visit(Scalar(self.target()))?;
        self.query_opened(&plaintext).map_err(OrderError::Backend)
    }

    /// Encrypt a plaintext [`order_terms`](crate::order_terms) collected
    /// from a whole value as a query.
    ///
    /// # Errors
    ///
    /// [`OrderError::Term`] with [`NormalizeError::Mismatch`] if it was
    /// encoded as another target than this space's, else as
    /// [`encrypt_query_checked`](Self::encrypt_query_checked).
    pub fn encrypt_query_term(
        &self,
        plaintext: &OrderPlaintext,
    ) -> Result<QueryTerm<S::Query, T>, OrderError<S::Error>> {
        if plaintext.target() != self.target() {
            return Err(OrderError::Term(NormalizeError::Mismatch));
        }
        self.supported()?;
        self.query_opened(plaintext).map_err(OrderError::Backend)
    }

    /// A query the scheme already made in this space, as the space's
    /// own: it then compares with the space's terms. The caller vouches
    /// that it was made here; the space cannot tell.
    pub fn query(&self, raw: S::Query) -> QueryTerm<S::Query, T> {
        QueryTerm {
            raw,
            target: self.target,
        }
    }

    /// The order of the value `query` encrypts relative to the value
    /// `term` encrypts, [`OrderQuery::compare_query`]: `Less` when the
    /// queried value sorts before the stored one.
    ///
    /// Both must be this space's, as [`compare`](Self::compare) asks of
    /// its terms: a query and a term of different targets, or of another
    /// target than this space's, are `None`.
    pub fn compare_query(
        &self,
        query: &QueryTerm<S::Query, T>,
        term: &OrderTerm<S::Term, T>,
    ) -> Option<Ordering> {
        let target = self.target();
        (query.target() == target && term.target() == target)
            .then(|| S::compare_query(&query.raw, term.raw()))
            .flatten()
    }

    /// Open the space if it is not, then make one query of it.
    fn query_opened(&self, plaintext: &OrderPlaintext) -> Result<QueryTerm<S::Query, T>, S::Error> {
        let opened = self.opened()?;
        self.scheme
            .encrypt_query(opened, plaintext)
            .map(|raw| self.query(raw))
    }
}

impl<S: OrderQuery + Supports<T> + Supports<OrderTarget> + ?Sized, T: StaticTarget>
    OrderSpace<'_, S, T>
{
    /// Encrypt a value that always fits this space's target as a query,
    /// as [`encrypt`](Self::encrypt) makes a term of one. The compiler
    /// refuses a value that might not fit, and names
    /// [`encrypt_query_checked`](Self::encrypt_query_checked) for it.
    ///
    /// The query is for the comparison at hand: held beside the stored
    /// terms it orders every one of them against the value, so it should
    /// not be persisted or logged. Under block ORE it is deterministic, so
    /// a log of queries is a log of what was searched (see
    /// [`OrderQuery`]).
    ///
    /// # Errors
    ///
    /// The scheme's own failure, and nothing else.
    pub fn encrypt_query<V: FitsIn<T>>(
        &self,
        value: V,
    ) -> Result<QueryTerm<S::Query, T>, S::Error> {
        let plaintext = match value.visit(Scalar(T::TARGET)) {
            Ok(plaintext) => plaintext,
            // As in `encrypt`: `FitsIn` is a sealed table the encoding
            // never refuses, exercised at its extremes by this crate's
            // tests.
            Err(refused) => unreachable!("a `FitsIn` value was refused: {refused}"),
        };
        self.query_opened(&plaintext)
    }
}
