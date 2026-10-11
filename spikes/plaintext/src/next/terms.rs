//! Equality terms as an ordinary sink. Encrypt-plus-terms is
//! `Tee(EncryptSink, Terms)`, with no special wrapper.
//!
//! Compare stage 1's `sinks/terms.rs`, which needed `Tracked` and
//! `WithTerms` to ride along inside the cipher's own walk.

use std::marker::PhantomData;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::IntoAad;
use vitaminc_aead_value::canonical::{CanonicalError, EqualityInput};

use super::encrypt::{Backend, EncryptError, EncryptSink, Node};
use super::model::{Error, MapSink, Plaintext, SeqSink, Sink};
use super::tee::Tee;
use crate::sinks::equality::EqualityTerm;
use crate::sinks::terms::{PathSeg, Term};
use crate::Sink as _;

/// Collects a term per scalar leaf. Never fails itself, so it takes on
/// whatever error type it's teed with.
pub struct Terms<'t, E> {
    out: &'t mut Vec<Term>,
    path: Vec<PathSeg>,
    _error: PhantomData<E>,
}

impl<'t, E> Terms<'t, E> {
    pub fn new(out: &'t mut Vec<Term>) -> Self {
        Self {
            out,
            path: Vec::new(),
            _error: PhantomData,
        }
    }

    fn record(self, input: Result<EqualityInput, CanonicalError>) -> Result<(), E> {
        match input {
            Err(CanonicalError::UnsupportedKind(_) | CanonicalError::UnsupportedValue) => {}
            input => self.out.push(Term {
                path: self.path,
                input,
            }),
        }
        Ok(())
    }
}

pub type WithTerms<B> = Result<(Node<<B as Backend>::Leaf>, Vec<Term>), EncryptError<<B as Backend>::Error>>;

/// Encrypt and collect terms in one walk.
pub fn encrypt_with_terms<'a, P, B, A>(
    p: P,
    backend: &B,
    aad: A,
) -> WithTerms<B>
where
    P: Plaintext,
    B: Backend,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let (ct, ()) = p.visit(Tee(EncryptSink::root(backend, aad), Terms::new(&mut terms)))?;
    Ok((ct, terms))
}

macro_rules! term {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<(), E> {
                self.record(EqualityTerm.$method(v))
            }
        )*
    };
}

impl<'t, E: Error> Sink for Terms<'t, E> {
    type Ok = ();
    type Error = E;
    type Seq = TermsSeq<'t, E>;
    type Map = TermsSeq<'t, E>;

    fn null(self) -> Result<(), E> {
        Ok(())
    }

    fn undefined(self) -> Result<(), E> {
        Ok(())
    }

    fn bool(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    term! {
        i8(i8), i16(i16), i32(i32), i64(i64), i128(i128),
        u8(u8), u16(u16), u32(u32), u64(u64), u128(u128),
        f32(f32), f64(f64),
        date(NaiveDate), timestamp(DateTime<Utc>), decimal(Decimal),
        str(&str), bytes(&[u8]),
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, E> {
        Ok(TermsSeq { parent: self, index: 0 })
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, E> {
        Ok(TermsSeq { parent: self, index: 0 })
    }

    /// Cleartext, so no terms.
    fn passthrough<P: Plaintext>(self, _: P) -> Result<(), E> {
        Ok(())
    }
}

/// Serves as both the sequence and the map sink: only the path differs.
pub struct TermsSeq<'t, E> {
    parent: Terms<'t, E>,
    index: usize,
}

impl<E> TermsSeq<'_, E> {
    fn child(&mut self, seg: PathSeg) -> Terms<'_, E> {
        let mut path = self.parent.path.clone();
        path.push(seg);
        Terms {
            out: &mut *self.parent.out,
            path,
            _error: PhantomData,
        }
    }
}

impl<'t, E: Error> SeqSink for TermsSeq<'t, E> {
    type Ok = ();
    type Error = E;
    type Element<'s>
        = Terms<'s, E>
    where
        Self: 's;

    fn element(&mut self) -> Result<Terms<'_, E>, E> {
        self.index += 1;
        Ok(self.child(PathSeg::Index(self.index - 1)))
    }

    fn end(self) -> Result<(), E> {
        Ok(())
    }
}

impl<'t, E: Error> MapSink for TermsSeq<'t, E> {
    type Ok = ();
    type Error = E;
    type Entry<'s>
        = Terms<'s, E>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Terms<'_, E>, E> {
        Ok(self.child(PathSeg::Key(key.to_owned())))
    }

    fn end(self) -> Result<(), E> {
        Ok(())
    }
}
