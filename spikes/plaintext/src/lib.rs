#![doc = include_str!("../README.md")]

pub mod model;
mod scalar;

pub mod sources {
    pub mod frame;
    pub mod rust;
    pub mod value;
}

pub mod sinks {
    pub mod encrypt;
    pub mod equality;
    pub mod frame_writer;
    pub mod terms;
    pub mod value_builder;
}

pub mod decrypt;
pub mod next;

pub mod hosts {
    pub mod go_guest;
    #[cfg(feature = "napi")]
    pub mod js;
}

pub use decrypt::FrameOut;
pub use model::{MapSink, Plaintext, SeqSink, Sink};
pub use sinks::encrypt::Tagged;
pub use sinks::equality::EqualityTerm;
pub use sinks::frame_writer::to_frame;
pub use sinks::terms::{encrypt_with_terms, PathSeg, Term};
pub use sinks::value_builder::to_value;
pub use sources::frame::{Frame, FrameError};
pub use sources::rust::Bytes;
