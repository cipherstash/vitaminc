//! Encrypt and derive equality terms in one walk of the source.
//!
//! [`WithTerms`] wraps any sink. For every scalar it records the equality
//! input, then passes the same scalar on to the wrapped sink. The source is
//! read once, so a ciphertext and its terms can't disagree. That matters for
//! JS, where reading a getter twice can give two different answers.
//!
//! Nesting works even though the cipher drives each element's walk itself
//! (`SeqCipher::encrypt_next` takes a value). The element is handed over
//! wrapped in [`Tracked`], which re-applies `WithTerms` to whatever sink the
//! cipher walks it with. The terms side only ever pushes onto a shared
//! `Vec`, so it never needs to drive a walk of its own.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::{Cipher, Encrypt, IntoAad};
use vitaminc_aead_value::canonical::{CanonicalError, EqualityInput};

use crate::model::{MapSink, Plaintext, SeqSink, Sink};
use crate::sinks::encrypt::Tagged;
use crate::sinks::equality::EqualityTerm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSeg {
    Index(usize),
    Key(String),
}

/// The equality input for one scalar leaf, and where it sits in the value.
#[derive(Debug)]
pub struct Term {
    pub path: Vec<PathSeg>,
    pub input: Result<EqualityInput, CanonicalError>,
}

/// Encrypt `p` with tagged leaves and collect a term for every leaf that has
/// one, reading `p` once.
pub fn encrypt_with_terms<'a, P, C, A>(
    p: P,
    cipher: C,
    aad: A,
) -> Result<(C::Ok, Vec<Term>), C::Error>
where
    P: Plaintext,
    C: Cipher,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let tracked = Tracked {
        value: p,
        terms: &mut terms,
        path: Vec::new(),
    };
    let ct = Tagged(tracked).encrypt_with_aad(cipher, aad)?;
    Ok((ct, terms))
}

/// A source plus the place its terms go. Whoever walks it gets `WithTerms`
/// wrapped around their sink.
pub struct Tracked<'t, P> {
    value: P,
    terms: &'t mut Vec<Term>,
    path: Vec<PathSeg>,
}

impl<P: Plaintext> Plaintext for Tracked<'_, P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.value.visit(WithTerms {
            inner: sink,
            terms: self.terms,
            path: self.path,
        })
    }
}

pub struct WithTerms<'t, S> {
    inner: S,
    terms: &'t mut Vec<Term>,
    path: Vec<PathSeg>,
}

impl<S> WithTerms<'_, S> {
    fn record(&mut self, input: Result<EqualityInput, CanonicalError>) {
        match input {
            // Kinds with no terms (bool, null, ...) are skipped, not errors.
            Err(CanonicalError::UnsupportedKind(_) | CanonicalError::UnsupportedValue) => {}
            input => self.terms.push(Term {
                path: self.path.clone(),
                input,
            }),
        }
    }
}

macro_rules! scalar {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(mut self, v: $ty) -> Result<S::Ok, S::Error> {
                self.record(EqualityTerm.$method(v));
                self.inner.$method(v)
            }
        )*
    };
}

impl<'t, S: Sink> Sink for WithTerms<'t, S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Seq = TermsSeq<'t, S::Seq>;
    type Map = TermsMap<'t, S::Map>;

    fn null(self) -> Result<S::Ok, S::Error> {
        self.inner.null()
    }

    fn undefined(self) -> Result<S::Ok, S::Error> {
        self.inner.undefined()
    }

    fn bool(self, v: bool) -> Result<S::Ok, S::Error> {
        self.inner.bool(v)
    }

    scalar! {
        i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u32(u32), u64(u64), u128(u128),
        f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal),
        str(&str), bytes(&[u8]),
    }

    fn seq(self, len: usize) -> Result<Self::Seq, S::Error> {
        Ok(TermsSeq {
            inner: self.inner.seq(len)?,
            terms: self.terms,
            path: self.path,
            index: 0,
        })
    }

    fn map(self, len: usize) -> Result<Self::Map, S::Error> {
        Ok(TermsMap {
            inner: self.inner.map(len)?,
            terms: self.terms,
            path: self.path,
        })
    }

    /// Passthrough travels in the clear, so it gets no terms.
    fn passthrough<P: Plaintext>(self, value: P) -> Result<S::Ok, S::Error> {
        self.inner.passthrough(value)
    }
}

fn child(path: &[PathSeg], seg: PathSeg) -> Vec<PathSeg> {
    let mut path = path.to_vec();
    path.push(seg);
    path
}

pub struct TermsSeq<'t, Q> {
    inner: Q,
    terms: &'t mut Vec<Term>,
    path: Vec<PathSeg>,
    index: usize,
}

impl<Q: SeqSink> SeqSink for TermsSeq<'_, Q> {
    type Ok = Q::Ok;
    type Error = Q::Error;

    fn element<P: Plaintext>(self, value: P) -> Result<Self, Q::Error> {
        let TermsSeq {
            inner,
            terms,
            path,
            index,
        } = self;
        let tracked = Tracked {
            value,
            terms: &mut *terms,
            path: child(&path, PathSeg::Index(index)),
        };
        let inner = inner.element(tracked)?;
        Ok(TermsSeq {
            inner,
            terms,
            path,
            index: index + 1,
        })
    }

    fn end(self) -> Result<Q::Ok, Q::Error> {
        self.inner.end()
    }
}

pub struct TermsMap<'t, M> {
    inner: M,
    terms: &'t mut Vec<Term>,
    path: Vec<PathSeg>,
}

impl<M: MapSink> MapSink for TermsMap<'_, M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn entry<P: Plaintext>(self, key: &str, value: P) -> Result<Self, M::Error> {
        let TermsMap { inner, terms, path } = self;
        let tracked = Tracked {
            value,
            terms: &mut *terms,
            path: child(&path, PathSeg::Key(key.to_owned())),
        };
        let inner = inner.entry(key, tracked)?;
        Ok(TermsMap { inner, terms, path })
    }

    fn end(self) -> Result<M::Ok, M::Error> {
        self.inner.end()
    }
}
