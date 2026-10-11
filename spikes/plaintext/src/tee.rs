//! Two sinks, one walk. This is what push-style containers buy.
//!
//! Today's `SeqCipher::encrypt_next` takes each element as a value and walks
//! it itself, so only one consumer can drive the walk. Here a tee asks both
//! sides for an element sink and hands the pair to the source. Any sinks
//! compose, at any depth.

use vitaminc_protected::Controlled;

use crate::frame::Frame;
use crate::frame_writer::{to_frame, FrameWriteError};
use crate::kinds::{Logical, Physical};
use crate::model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};

pub struct Tee<A, B>(pub A, pub B);

impl<A: Sink, B: Sink<Error = A::Error>> Sink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Seq = Tee<A::Seq, B::Seq>;
    type Map = Tee<A::Map, B::Map>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<Self::Ok, A::Error> {
        Ok((self.0.scalar(ty, v)?, self.1.scalar(ty, v)?))
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, A::Error> {
        Ok(Tee(self.0.seq(len)?, self.1.seq(len)?))
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, A::Error> {
        Ok(Tee(self.0.map(len)?, self.1.map(len)?))
    }

    /// The one place a tee can't share a walk: `passthrough` hands each sink
    /// a whole subtree to walk itself. So it's framed once and both sides
    /// walk the frame. Passthrough is cleartext, so the copy is harmless.
    fn passthrough<P: Plaintext>(self, value: P) -> Result<Self::Ok, A::Error> {
        let bytes = to_frame(value).map_err(|e| match e {
            FrameWriteError::Source(e) => A::Error::source(e),
            other => A::Error::source(SourceError::msg(format!("{other:?}"))),
        })?;
        let frame = Frame::parse(bytes.risky_ref())
            .map_err(|_| A::Error::source(SourceError::msg("passthrough frame")))?;
        Ok((self.0.passthrough(frame)?, self.1.passthrough(frame)?))
    }
}

impl<A: SeqSink, B: SeqSink<Error = A::Error>> SeqSink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Element<'s>
        = Tee<A::Element<'s>, B::Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, A::Error> {
        Ok(Tee(self.0.element()?, self.1.element()?))
    }

    fn end(self) -> Result<Self::Ok, A::Error> {
        Ok((self.0.end()?, self.1.end()?))
    }
}

impl<A: MapSink, B: MapSink<Error = A::Error>> MapSink for Tee<A, B> {
    type Ok = (A::Ok, B::Ok);
    type Error = A::Error;
    type Entry<'s>
        = Tee<A::Entry<'s>, B::Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, A::Error> {
        Ok(Tee(self.0.entry(key)?, self.1.entry(key)?))
    }

    fn end(self) -> Result<Self::Ok, A::Error> {
        Ok((self.0.end()?, self.1.end()?))
    }
}
