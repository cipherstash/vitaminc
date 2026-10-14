//! Leaf type tags — the cross-language wire commitment.
//!
//! The table lives in [`vitaminc_aead::tags`] alongside the leaf codec, so
//! that the sealed leaf, the transport frame and this value model cannot
//! drift apart on meaning. This module re-exports it unchanged.
//!
//! Every scalar [`Value`](crate::Value) seals as `[tag] ++ payload`
//! **inside** the AEAD envelope, so the tag is authenticated. Containers
//! (arrays, objects) are structural — they use the cipher's sequence and map
//! modes and carry no tag.
//!
//! # ⚠️ Frozen wire format
//!
//! These constants and their payload encodings are shared by every language
//! binding and are pinned byte-for-byte by known-answer tests. Changing one
//! breaks decryption of existing ciphertexts everywhere. New types must be
//! assigned **new** tags; tags are never reused or renumbered.

pub use vitaminc_aead::tags::*;
