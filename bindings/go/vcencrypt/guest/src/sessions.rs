//! The cipher-session table behind the ABI's handle scheme. Kept out of the
//! wasm32-gated [`crate::abi`] module so the handle-allocation invariants can
//! be unit-tested natively.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use vitaminc_encrypt::Aes256Cipher;

use crate::status::{STATUS_ENCODING, STATUS_INTERNAL};

pub(crate) struct Sessions {
    next: u32,
    ciphers: HashMap<u32, Aes256Cipher>,
}

impl Sessions {
    pub(crate) fn new() -> Self {
        // Handle ids start at 1 so a zero high-field can never be a valid
        // handle (see the abi result encoding).
        Sessions {
            next: 1,
            ciphers: HashMap::new(),
        }
    }

    /// Insert a cipher under a fresh handle id.
    ///
    /// Refuses at id exhaustion rather than wrapping or saturating: a reused
    /// id would alias a live handle and silently displace its session —
    /// sealing new data under the wrong key and orphaning everything the
    /// displaced key had sealed. `next` only advances on success, and the
    /// occupancy check makes the no-aliasing invariant explicit rather than
    /// assumed. (The final id, `u32::MAX`, is sacrificed to keep the
    /// arithmetic simple; ~4.3e9 handles precede it.)
    pub(crate) fn insert(&mut self, cipher: Aes256Cipher) -> Result<u32, u32> {
        let handle = self.next;
        let bumped = handle.checked_add(1).ok_or(STATUS_INTERNAL)?;
        match self.ciphers.entry(handle) {
            Entry::Occupied(_) => Err(STATUS_INTERNAL),
            Entry::Vacant(slot) => {
                slot.insert(cipher);
                self.next = bumped;
                Ok(handle)
            }
        }
    }

    pub(crate) fn get(&self, handle: u32) -> Option<&Aes256Cipher> {
        self.ciphers.get(&handle)
    }

    pub(crate) fn remove(&mut self, handle: u32) {
        self.ciphers.remove(&handle);
    }
}

/// Build a cipher from raw key bytes, zeroizing the guest-side stack copy of
/// the key material once the cipher (and its key schedule) owns it. The key
/// schedule inside `Aes256Cipher` is wiped best-effort when the cipher is
/// dropped; that wipe is owned by the crypto backend.
pub(crate) fn build_cipher(key: &[u8]) -> Result<Aes256Cipher, u32> {
    use vitaminc_encrypt::Key;
    use zeroize::Zeroize;

    // Length is validated here (not just by try_into) so a host
    // pointer/length desync surfaces as STATUS_ENCODING, distinguishable
    // from a crypto-backend failure.
    let mut key_copy: [u8; 32] = key.try_into().map_err(|_| STATUS_ENCODING)?;
    let cipher = Aes256Cipher::new(&Key::from(key_copy)).map_err(|_| STATUS_INTERNAL);
    key_copy.zeroize();
    cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> Aes256Cipher {
        build_cipher(&[0u8; 32]).expect("cipher")
    }

    #[test]
    fn handles_start_at_one_and_increment() {
        let mut s = Sessions::new();
        assert_eq!(s.insert(cipher()), Ok(1));
        assert_eq!(s.insert(cipher()), Ok(2));
        assert!(s.get(1).is_some());
        s.remove(1);
        assert!(s.get(1).is_none());
        assert!(s.get(2).is_some());
    }

    #[test]
    fn handle_ids_are_never_reused_at_exhaustion() {
        let mut s = Sessions::new();
        s.next = u32::MAX - 1;
        let last = s.insert(cipher()).expect("last issuable id");
        assert_eq!(last, u32::MAX - 1);
        // At exhaustion the table must refuse rather than alias a live
        // handle (a saturating or wrapping counter would silently displace
        // the session and seal under the wrong key).
        assert_eq!(s.insert(cipher()), Err(STATUS_INTERNAL));
        assert!(s.get(last).is_some(), "live session must not be displaced");
    }

    #[test]
    fn wrong_length_key_is_an_encoding_error() {
        assert_eq!(build_cipher(&[0u8; 16]).err(), Some(STATUS_ENCODING));
        assert_eq!(build_cipher(&[0u8; 33]).err(), Some(STATUS_ENCODING));
    }
}
