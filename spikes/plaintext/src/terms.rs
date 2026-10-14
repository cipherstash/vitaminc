//! Equality terms as an ordinary sink. Encrypt-plus-terms is
//! `Tee(EncryptSink, Terms)`, with no special wrapper.
//!
//! The encodings differ by type: an integer's sign byte depends on its
//! value, and a timestamp is a timestamp, not the integer it's stored as.
//! So the sink has to be told what each scalar is rather than handed bytes,
//! which is the information today's bytes-only `Cipher` drops. Output
//! matches `canonical::equality_input(&Value)` exactly (tested).

use std::marker::PhantomData;

use vitaminc_aead::IntoAad;
use vitaminc_aead_value::canonical::{domain, equality_input, text_nfc, CanonicalError, EqualityInput};
use vitaminc_aead_value::Value;
use vitaminc_protected::{Controlled, Protected};

use crate::encrypt::{AsyncBackend, Backend, EncryptError, EncryptSink, Node, Pending};
use crate::kinds::{self, Float, Int, Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink};
use crate::tee::Tee;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSeg {
    Index(usize),
    Key(String),
}

/// The equality input for one scalar leaf, and where it sits in the value.
#[derive(Debug)]
pub struct Term {
    pub path: Vec<PathSeg>,
    pub input: Result<EqualityInput, TermError>,
}

pub type WithTerms<B> = Result<(Node<<B as Backend>::Leaf>, Vec<Term>), EncryptError<<B as Backend>::Error>>;

pub type WithTermsAsync<B> = Result<(Node<<B as AsyncBackend>::Leaf>, Vec<Term>), EncryptError<<B as AsyncBackend>::Error>>;

/// Plan and collect terms in one walk. No backend yet: the terms are
/// complete before any leaf is sealed.
pub fn plan_with_terms<'a, P, E, A>(p: P, aad: A) -> Result<(Node<Pending>, Vec<Term>), EncryptError<E>>
where
    P: Plaintext,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let (node, ()) = p.visit(Tee(EncryptSink::root(aad), Terms::new(&mut terms)))?;
    Ok((node, terms))
}

/// Encrypt and collect terms in one walk.
pub fn encrypt_with_terms<'a, P, B, A>(p: P, backend: &B, aad: A) -> WithTerms<B>
where
    P: Plaintext,
    B: Backend,
    A: IntoAad<'a>,
{
    let (node, terms) = plan_with_terms(p, aad)?;
    Ok((crate::encrypt::seal_all(backend, node)?, terms))
}

/// Encrypt through an async backend and collect terms in one walk.
pub async fn encrypt_with_terms_async<'a, P, B, A>(p: P, backend: &B, aad: A) -> WithTermsAsync<B>
where
    P: Plaintext,
    B: AsyncBackend,
    A: IntoAad<'a>,
{
    let (node, terms) = plan_with_terms(p, aad)?;
    Ok((crate::encrypt::seal_all_async(backend, node).await?, terms))
}

/// The canonical integer layout, written natively: sign byte, then the
/// value as a big-endian two's-complement u128. Every width shares one
/// domain, so the width never reaches the term.
fn integer(i: Int) -> Result<EqualityInput, CanonicalError> {
    let (negative, word) = i.sign_and_word();
    let word = Protected::new(word.to_be_bytes());
    let mut bytes = Protected::new(Vec::with_capacity(17));
    bytes.risky_inner_mut().push(u8::from(!negative));
    bytes.risky_inner_mut().extend_from_slice(word.risky_ref());
    Ok(EqualityInput {
        domain: domain::INTEGER,
        bytes,
    })
}

/// SPIKE: the float, date, timestamp, decimal and bytes encodings are
/// private to aead-value's `canonical` module, which only exposes them
/// through `equality_input(&Value)`. So this builds a one-scalar `Value`
/// for them. With the encodings exposed per scalar this would go away.
fn via_value(v: Value) -> Result<EqualityInput, CanonicalError> {
    equality_input(&v)
}

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
}

/// The equality input for one scalar, or `None` if it has no term.
///
/// Logical types are opt-in. Each one the index knows gets its own domain
/// and its own normalization: a timestamp's unit is folded away here, so a
/// JS `Date` (milliseconds) matches the same instant from Rust
/// (nanoseconds). A logical type the index doesn't know is refused, never
/// indexed as its physical value: a decimal's mantissa isn't its value, and
/// a date's day count mustn't match the integer it happens to equal.
pub fn equality(ty: Option<Logical>, v: Physical<'_>) -> Option<Result<EqualityInput, TermError>> {
    let canonical = |r: Result<EqualityInput, CanonicalError>| Some(r.map_err(TermError::Canonical));
    let invalid = || Some(Err(TermError::Invalid));
    match (ty, v) {
        (None | Some(Logical::Undefined), Physical::Null) | (None, Physical::Bool(_)) => None,
        (None, Physical::Int(i)) => canonical(integer(i)),
        (None, Physical::Float(Float::F32(f))) => canonical(via_value(Value::Float32(f))),
        (None, Physical::Float(Float::F64(f))) => canonical(via_value(Value::Float64(f))),
        (None, Physical::Text(s)) => canonical(text_nfc(s.as_bytes()).map(|bytes| EqualityInput {
            domain: domain::TEXT,
            bytes,
        })),
        (None, Physical::Bytes(b)) => canonical(via_value(Value::Bytes(Protected::new(b.to_vec())))),
        (Some(Logical::Date), Physical::Int(i)) => match kinds::date(i) {
            Some(d) => canonical(via_value(Value::Date(d))),
            None => invalid(),
        },
        (Some(Logical::Timestamp(unit)), Physical::Int(i)) => match kinds::timestamp(unit, i) {
            Some(ts) => canonical(via_value(Value::Timestamp(ts))),
            None => invalid(),
        },
        (Some(Logical::Decimal { scale }), Physical::Int(i)) => match kinds::decimal(scale, i) {
            Some(d) => canonical(via_value(Value::Decimal(d))),
            None => invalid(),
        },
        // Uuid could reuse the bytes encoding under its own domain label.
        // That's a protocol decision, so it's refused until someone makes it.
        (Some(ty), _) => Some(Err(TermError::NoDomain(ty))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermError {
    Canonical(CanonicalError),
    /// A logical type this index has no domain for.
    NoDomain(Logical),
    /// A value that isn't valid for its logical type.
    Invalid,
}

impl<'t, E: Error> Sink for Terms<'t, E> {
    type Ok = ();
    type Error = E;
    type Seq = TermsSeq<'t, E>;
    type Map = TermsSeq<'t, E>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), E> {
        if let Some(input) = equality(ty, v) {
            self.out.push(Term { path: self.path, input });
        }
        Ok(())
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
