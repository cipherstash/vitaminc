//! `terms` and `encrypt_with_terms` agree on every value: each accepts
//! what the other accepts, with the same terms, and refuses what the other
//! refuses, for the same reason at the same path. One case per rule
//! encryption keeps, and per refusal of `Terms`'s own.

use std::collections::BTreeMap;

use vitaminc_aead::frame::MAX_DEPTH;
use vitaminc_aead::plaintext::render;
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{
    Context, EncryptError, Logical, MapSink, Physical, Plaintext, Raw, SeqSink, Sink, SourceError,
    Unencryptable,
};
use vitaminc_normalize::{encrypt_with_terms, terms, NormalizeError, Term, TermError};
use vitaminc_protected::{Controlled, Protected};

/// Seals in the clear: these tests are about the walk, not the cipher.
struct Clear;

impl Cipher for Clear {
    type Leaf = Vec<u8>;
    type Error = &'static str;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        _: &Context<'_>,
    ) -> Result<Vec<u8>, &'static str> {
        Ok(plaintext.risky_unwrap())
    }

    fn open(&self, leaf: Vec<u8>, _: &Context<'_>) -> Result<Protected<Vec<u8>>, &'static str> {
        Ok(Protected::new(leaf))
    }
}

/// How a walk ended, with every path written out.
#[derive(Debug, PartialEq)]
enum Outcome {
    Terms(Vec<String>),
    Shape(Unencryptable, String),
    Term(NormalizeError, String),
    Source(String),
}

use Outcome::{Shape, Source, Term as NoTerm, Terms};

fn paths(found: &[Term]) -> Outcome {
    Terms(found.iter().map(|t| render(&t.path)).collect())
}

fn sourced(source: &SourceError) -> Outcome {
    match source.inner().downcast_ref::<TermError>() {
        Some(term) => NoTerm(term.error(), render(term.path())),
        None => Source(source.to_string()),
    }
}

fn alone<P: Plaintext>(value: P) -> Outcome {
    match terms(value) {
        Ok(found) => paths(&found),
        Err(err) => match err.refusal() {
            Some(refusal) => Shape(refusal.reason(), render(refusal.path())),
            None => sourced(err.source_error()),
        },
    }
}

fn encrypting<P: Plaintext>(value: P) -> Outcome {
    match encrypt_with_terms(value, &Clear, "ctx") {
        Ok((_, found)) => paths(&found),
        Err(EncryptError::Shape(refusal)) => Shape(refusal.reason(), render(refusal.path())),
        Err(EncryptError::Source(source)) => sourced(&source),
        Err(other) => panic!("{other:?}"),
    }
}

/// `value()` ends the same way both walks, and that way is `expected`.
#[track_caller]
fn agree<P: Plaintext>(value: impl Fn() -> P, expected: Outcome) {
    assert_eq!(encrypting(value()), expected, "encrypt_with_terms");
    assert_eq!(alone(value()), expected, "terms");
}

fn shape(reason: Unencryptable, at: &str) -> Outcome {
    Shape(reason, at.to_owned())
}

/// A document whose `users` entry is a sequence of two values, the second
/// of them `bad`, beside a well-formed `id`, so every refusal below the
/// root has a path with a key and an index in it.
#[derive(Clone)]
struct Users<P>(P);

impl<P: Plaintext> Plaintext for Users<P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(2))?;
        1u32.visit(map.entry("id")?)?;
        let mut users = map.entry("users")?.seq(Some(2))?;
        "ada".visit(users.element()?)?;
        self.0.visit(users.element()?)?;
        users.end()?;
        map.end()
    }
}

/// A map that gives `k` twice.
#[derive(Clone)]
struct Dup;

impl Plaintext for Dup {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(None)?;
        "one".visit(map.entry("k")?)?;
        "two".visit(map.entry("k")?)?;
        map.end()
    }
}

/// A container with one passthrough in it and nothing sealed.
#[derive(Clone)]
struct OnlyPass {
    map: bool,
}

impl Plaintext for OnlyPass {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        if self.map {
            let mut map = sink.map(Some(1))?;
            map.entry("note")?.passthrough("public")?;
            map.end()
        } else {
            let mut seq = sink.seq(Some(1))?;
            seq.element()?.passthrough("public")?;
            seq.end()
        }
    }
}

/// A container whose source takes a child sink and drops it unused.
#[derive(Clone)]
struct DropsAChild {
    map: bool,
}

impl Plaintext for DropsAChild {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        if self.map {
            let mut map = sink.map(None)?;
            let _ = map.entry("a")?;
            "b".visit(map.entry("b")?)?;
            map.end()
        } else {
            let mut seq = sink.seq(None)?;
            "a".visit(seq.element()?)?;
            let _ = seq.element()?;
            seq.end()
        }
    }
}

/// A passthrough that opens a container and never ends it.
#[derive(Clone)]
struct Unclosed;

impl Plaintext for Unclosed {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut outer = sink.seq(None)?;
        let mut inner = outer.element()?.seq(None)?;
        1u32.visit(inner.element()?)?;
        drop(inner);
        outer.end()
    }
}

/// `inner` as a passthrough, beside a sealed sibling.
#[derive(Clone)]
struct Passes<P>(P);

impl<P: Plaintext + Clone> Plaintext for Passes<P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut seq = sink.seq(Some(2))?;
        "sealed".visit(seq.element()?)?;
        seq.element()?.passthrough(self.0)?;
        seq.end()
    }
}

/// A source whose getter throws.
#[derive(Clone)]
struct Throws;

impl Plaintext for Throws {
    fn visit<S: Sink>(self, _: S) -> Result<S::Ok, S::Error> {
        Err(<S::Error as vitaminc_aead::plaintext::Error>::source(
            SourceError::msg("getter threw"),
        ))
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Seq,
    Map,
    Pass,
    Scalar,
}

/// `n` levels of one kind of nesting around an innermost value at depth
/// `n`: an empty sequence, or for `Scalar`, a string inside sequences.
#[derive(Clone, Copy)]
struct Nest(Kind, usize);

impl Plaintext for Nest {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let Nest(kind, n) = self;
        if n == 0 {
            return match kind {
                Kind::Scalar => "deep".visit(sink),
                _ => sink.seq(Some(0))?.end(),
            };
        }
        let inner = Nest(kind, n - 1);
        match kind {
            Kind::Seq | Kind::Scalar => {
                let mut seq = sink.seq(Some(1))?;
                inner.visit(seq.element()?)?;
                seq.end()
            }
            Kind::Map => {
                let mut map = sink.map(Some(1))?;
                inner.visit(map.entry("k")?)?;
                map.end()
            }
            Kind::Pass => sink.passthrough(inner),
        }
    }
}

#[test]
fn both_accept_a_well_formed_value_with_the_same_terms() {
    let doc = || {
        let mut doc = BTreeMap::new();
        doc.insert("ages", vec![Some(36u32), None]);
        doc.insert("empty", vec![]);
        doc
    };
    agree(doc, Terms(vec![".ages[0]".into()]));
    // A passthrough beside a sealed sibling, and nesting right up to the
    // limit, are fine.
    agree(|| Passes("public"), Terms(vec!["[0]".into()]));
    agree(
        || Nest(Kind::Scalar, MAX_DEPTH),
        Terms(vec!["[0]".repeat(MAX_DEPTH)]),
    );
    agree(|| Nest(Kind::Map, MAX_DEPTH), Terms(Vec::new()));
}

#[test]
fn both_refuse_a_duplicate_key_at_the_repeated_entry() {
    agree(
        || Users(Dup),
        shape(Unencryptable::DuplicateKey, ".users[1].k"),
    );
    agree(|| Dup, shape(Unencryptable::DuplicateKey, ".k"));
}

#[test]
fn both_refuse_a_container_with_nothing_sealed() {
    agree(
        || Users(OnlyPass { map: false }),
        shape(Unencryptable::SequenceHasNothingSealed, ".users[1]"),
    );
    agree(
        || Users(OnlyPass { map: true }),
        shape(Unencryptable::MapHasNothingSealed, ".users[1]"),
    );
    agree(
        || OnlyPass { map: false },
        shape(Unencryptable::SequenceHasNothingSealed, ""),
    );
}

#[test]
fn both_refuse_a_dropped_child_sink() {
    for map in [false, true] {
        agree(
            || Users(DropsAChild { map }),
            shape(Unencryptable::DroppedChild, ".users[1]"),
        );
    }
}

#[test]
fn both_refuse_a_value_invalid_for_its_logical_type() {
    let invalid = || Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]));
    agree(
        || Users(invalid()),
        shape(Unencryptable::InvalidValue, ".users[1]"),
    );
    // `undefined` over an int has no term either, but is refused all the
    // same: it cannot be encrypted.
    agree(
        || {
            Raw(
                Some(Logical::Undefined),
                Physical::Int(vitaminc_aead::Int::I8(1)),
            )
        },
        shape(Unencryptable::InvalidValue, ""),
    );
}

#[test]
fn both_refuse_a_passthrough_that_does_not_frame_at_the_passthrough() {
    agree(
        || Passes(Unclosed),
        shape(Unencryptable::UnframablePassthrough, "[1]"),
    );
    agree(
        || Passes(Dup),
        shape(Unencryptable::UnframablePassthrough, "[1]"),
    );
    // A source error inside the passthrough is the source's, both ways.
    agree(|| Passes(Throws), Source("getter threw".into()));
}

#[test]
fn both_refuse_a_value_nested_too_deep_at_the_same_node() {
    for (kind, step) in [(Kind::Seq, "[0]"), (Kind::Map, ".k"), (Kind::Scalar, "[0]")] {
        agree(
            || Nest(kind, MAX_DEPTH + 1),
            shape(Unencryptable::TooDeep, &step.repeat(MAX_DEPTH + 1)),
        );
    }
    // A passthrough too deep, or with too much inside it, is refused as a
    // whole at its own place.
    agree(
        || Nest(Kind::Pass, MAX_DEPTH + 1),
        shape(Unencryptable::TooDeep, ""),
    );
    agree(
        || Passes(Nest(Kind::Seq, MAX_DEPTH - 1)),
        shape(Unencryptable::TooDeep, "[1]"),
    );
    agree(
        || Users(Nest(Kind::Seq, MAX_DEPTH - 1)),
        shape(
            Unencryptable::TooDeep,
            &format!(".users[1]{}", "[0]".repeat(MAX_DEPTH - 1)),
        ),
    );
}

#[test]
fn both_refuse_what_terms_refuses_with_the_same_term_error() {
    agree(
        || Users("\u{378}"),
        NoTerm(NormalizeError::UnassignedCodePoint, ".users[1]".into()),
    );
    let newer = || {
        Users(Raw(
            Some(Logical::from_wire(200, 0).expect("unknown")),
            Physical::Bytes(b"x"),
        ))
    };
    agree(newer, NoTerm(NormalizeError::NoDomain, ".users[1]".into()));
}

#[test]
fn both_pass_a_source_failure_through() {
    agree(|| Users(Throws), Source("getter threw".into()));
}
