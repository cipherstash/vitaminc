//! Equality terms as an ordinary sink. Encrypt-plus-terms is
//! `Tee(EncryptSink, Terms)`, with no special wrapper.
//!
//! The encodings differ by type: a signed integer gets a sign byte that
//! depends on its value, an unsigned one always gets `1`. So the sink has to
//! be told "this is an i32" rather than handed four bytes, which is the
//! information today's bytes-only `Cipher` drops. Output matches
//! `canonical::equality_input(&Value)` exactly (tested).

use std::marker::PhantomData;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use vitaminc_aead::IntoAad;
use vitaminc_aead_value::canonical::{domain, equality_input, text_nfc, CanonicalError, EqualityInput};
use vitaminc_aead_value::Value;
use vitaminc_protected::{Controlled, Protected};

use crate::encrypt::{Backend, EncryptError, EncryptSink, Node};
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
    pub input: Result<EqualityInput, CanonicalError>,
}

pub type WithTerms<B> = Result<(Node<<B as Backend>::Leaf>, Vec<Term>), EncryptError<<B as Backend>::Error>>;

/// Encrypt and collect terms in one walk.
pub fn encrypt_with_terms<'a, P, B, A>(p: P, backend: &B, aad: A) -> WithTerms<B>
where
    P: Plaintext,
    B: Backend,
    A: IntoAad<'a>,
{
    let mut terms = Vec::new();
    let (ct, ()) = p.visit(Tee(EncryptSink::root(backend, aad), Terms::new(&mut terms)))?;
    Ok((ct, terms))
}

/// The canonical integer layout, written natively: sign byte, then the
/// value as a big-endian u128. Every width shares one domain.
fn integer(sign: u8, word: u128) -> Result<EqualityInput, CanonicalError> {
    let word = Protected::new(word.to_be_bytes());
    let mut bytes = Protected::new(Vec::with_capacity(17));
    bytes.risky_inner_mut().push(sign);
    bytes.risky_inner_mut().extend_from_slice(word.risky_ref());
    Ok(EqualityInput {
        domain: domain::INTEGER,
        bytes,
    })
}

fn signed(v: i128) -> Result<EqualityInput, CanonicalError> {
    integer((!(v >> 127) & 1) as u8, v as u128)
}

fn unsigned(v: u128) -> Result<EqualityInput, CanonicalError> {
    integer(1, v)
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

    fn record(self, input: Result<EqualityInput, CanonicalError>) -> Result<(), E> {
        self.out.push(Term { path: self.path, input });
        Ok(())
    }
}

macro_rules! term {
    ($($method:ident($ty:ty) => $f:expr),* $(,)?) => {
        $(
            fn $method(self, v: $ty) -> Result<(), E> {
                self.record($f(v))
            }
        )*
    };
}

impl<'t, E: Error> Sink for Terms<'t, E> {
    type Ok = ();
    type Error = E;
    type Seq = TermsSeq<'t, E>;
    type Map = TermsSeq<'t, E>;

    // Null, undefined and booleans have no terms.
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
        i8(i8) => |v: i8| signed(v.into()),
        i16(i16) => |v: i16| signed(v.into()),
        i32(i32) => |v: i32| signed(v.into()),
        i64(i64) => |v: i64| signed(v.into()),
        i128(i128) => signed,
        u8(u8) => |v: u8| unsigned(v.into()),
        u16(u16) => |v: u16| unsigned(v.into()),
        u32(u32) => |v: u32| unsigned(v.into()),
        u64(u64) => |v: u64| unsigned(v.into()),
        u128(u128) => unsigned,
        f32(f32) => |v| via_value(Value::Float32(v)),
        f64(f64) => |v| via_value(Value::Float64(v)),
        date(NaiveDate) => |v| via_value(Value::Date(v)),
        timestamp(DateTime<Utc>) => |v| via_value(Value::Timestamp(v)),
        decimal(Decimal) => |v| via_value(Value::Decimal(v)),
        bytes(&[u8]) => |v: &[u8]| via_value(Value::Bytes(Protected::new(v.to_vec()))),
    }

    fn str(self, v: &str) -> Result<(), E> {
        let input = text_nfc(v.as_bytes()).map(|bytes| EqualityInput {
            domain: domain::TEXT,
            bytes,
        });
        self.record(input)
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
