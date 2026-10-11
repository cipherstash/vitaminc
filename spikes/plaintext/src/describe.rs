//! A sink that prints what a source says, physical and logical. For tests
//! and for poking around: `describe(Frame::parse(bytes)?)`.

use std::fmt::Write;

use crate::kinds::{Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};

#[derive(Debug)]
pub struct DescribeError(pub SourceError);

impl Error for DescribeError {
    fn source(error: SourceError) -> Self {
        Self(error)
    }
}

/// `date i32 19782`, `u32 34`, `[f64 2.5, null]`, `{"a": "x"}`.
pub fn describe<P: Plaintext>(p: P) -> Result<String, DescribeError> {
    let mut out = String::new();
    p.visit(Describe(&mut out))?;
    Ok(out)
}

pub struct Describe<'o>(pub &'o mut String);

impl<'o> Sink for Describe<'o> {
    type Ok = ();
    type Error = DescribeError;
    type Seq = List<'o>;
    type Map = List<'o>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), DescribeError> {
        match ty {
            Some(ty) => write!(self.0, "{ty} {v}"),
            None => write!(self.0, "{v}"),
        }
        .map_err(|e| DescribeError(SourceError(e.into())))
    }

    fn seq(self, _: Option<usize>) -> Result<List<'o>, DescribeError> {
        self.0.push('[');
        Ok(List { out: self.0, first: true, close: ']' })
    }

    fn map(self, _: Option<usize>) -> Result<List<'o>, DescribeError> {
        self.0.push('{');
        Ok(List { out: self.0, first: true, close: '}' })
    }

    fn passthrough<P: Plaintext>(self, value: P) -> Result<(), DescribeError> {
        self.0.push_str("passthrough ");
        value.visit(self)
    }
}

pub struct List<'o> {
    out: &'o mut String,
    first: bool,
    close: char,
}

impl List<'_> {
    fn next(&mut self) {
        if !self.first {
            self.out.push_str(", ");
        }
        self.first = false;
    }
}

impl SeqSink for List<'_> {
    type Ok = ();
    type Error = DescribeError;
    type Element<'s>
        = Describe<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<Describe<'_>, DescribeError> {
        self.next();
        Ok(Describe(self.out))
    }

    fn end(self) -> Result<(), DescribeError> {
        self.out.push(self.close);
        Ok(())
    }
}

impl MapSink for List<'_> {
    type Ok = ();
    type Error = DescribeError;
    type Entry<'s>
        = Describe<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Describe<'_>, DescribeError> {
        self.next();
        let _ = write!(self.out, "{key:?}: ");
        Ok(Describe(self.out))
    }

    fn end(self) -> Result<(), DescribeError> {
        self.out.push(self.close);
        Ok(())
    }
}
