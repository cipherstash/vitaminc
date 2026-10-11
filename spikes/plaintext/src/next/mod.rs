//! Stage 2: the data model with vitaminc's APIs open to change.
//!
//! No `Encrypt`, no `Decrypt`, no `Value`. See the README for what changed
//! and why.

pub mod codec;
pub mod decrypt;
pub mod encrypt;
pub mod frame_writer;
pub mod model;
pub mod sources;
pub mod tee;
pub mod terms;
pub mod typed;

pub use decrypt::{decrypt_into, DecryptError};
pub use encrypt::{encrypt, Backend, EncryptError, Node, PassthroughFrame};
pub use frame_writer::to_frame;
pub use model::{Error, MapSink, Plaintext, SeqSink, Sink, SourceError};
pub use tee::Tee;
pub use terms::encrypt_with_terms;
pub use typed::{decrypt_as, Decode, DecodeError};
