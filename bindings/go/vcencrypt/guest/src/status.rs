//! Status codes for the ABI's packed result encoding (see [`crate::abi`]).
//! Defined outside the wasm32-gated ABI module so native builds — the codec
//! unit tests and the fixture generator — can reference them too. The Go
//! host mirrors these values (`client.go`'s `status*` constants); they are
//! part of the guest/host contract and must not be renumbered.

/// AEAD open failure: wrong key, wrong AAD, or tampered ciphertext.
pub const STATUS_AUTH: u32 = 1;
/// Invalid input at the boundary: malformed transport bytes, a wrong-length
/// key, or a pointer/length pair that fails validation against linear
/// memory.
pub const STATUS_ENCODING: u32 = 2;
/// The handle is unknown (never issued, or already freed).
pub const STATUS_BAD_HANDLE: u32 = 3;
/// A cipher that could not be constructed, handle-id exhaustion, a caught
/// panic (unwind builds only), or any other unexpected internal failure.
pub const STATUS_INTERNAL: u32 = 4;
