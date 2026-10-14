#![doc = include_str!("../README.md")]

pub mod codec;
pub mod decrypt;
pub mod describe;
pub mod encrypt;
pub mod frame;
pub mod frame_writer;
pub mod kinds;
pub mod model;
pub mod scalar;
pub mod sources;
pub mod tee;
pub mod terms;
pub mod typed;

pub mod hosts {
    pub mod go_guest;
    #[cfg(feature = "napi")]
    pub mod js;
}

pub use decrypt::{decrypt_into, decrypt_into_async, open_all, open_all_async, walk, DecryptError, Opened};
pub use describe::describe;
pub use encrypt::{
    encrypt, encrypt_async, plan, seal_all, seal_all_async, AsyncBackend, Backend, EncryptError, Node, PassthroughFrame, Pending,
};
pub use frame::{Frame, FrameError};
pub use frame_writer::{to_frame, FrameWriter};
pub use kinds::{Float, Int, Logical, Physical, TimeUnit};
pub use model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
pub use sources::{Bytes, Raw, Uuid};
pub use tee::Tee;
pub use terms::{encrypt_with_terms, encrypt_with_terms_async, plan_with_terms, PathSeg, Term, TermError};
pub use typed::{decrypt_as, decrypt_as_async, Decode, DecodeError};
