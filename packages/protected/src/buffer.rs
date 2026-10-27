use core::ops::{Deref, DerefMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::locked::wipe_vec;

/// Secret bytes on the heap, written a few at a time: a frame, a blob, a
/// serialisation of a value.
///
/// A `Vec<u8>` that outgrows its allocation frees the old one with the
/// bytes still in it, and `zeroize` wipes a `Vec<u8>` one byte a store. A
/// `Buffer` does neither. It grows into a fresh allocation and wipes the
/// old one before it is freed; and it is wiped sixteen bytes a store, when
/// it is dropped, when it is [`zeroize`]d, and when it is [`clear`]ed. So
/// [`Protected<Buffer>`](crate::Protected) is what a writer of secret bytes
/// returns, and `&mut Buffer` is what it writes into.
///
/// It is a slice for reading and for patching bytes in place, through
/// `Deref`. Every way to add bytes goes through [`reserve`], so there is no
/// way to grow it that leaves a copy behind. It is not `Clone` and has no
/// `PartialEq`: its bytes are secret, so a copy or a comparison is a
/// decision to make at the use, through the slice.
///
/// [`zeroize`]: Zeroize::zeroize
/// [`clear`]: Buffer::clear
/// [`reserve`]: Buffer::reserve
///
/// # Examples
///
/// ```
/// use vitaminc_protected::{Buffer, Controlled, Protected};
///
/// let mut out = Buffer::new();
/// out.push(0x01);
/// out.extend_from_slice(b"secret");
/// assert_eq!(&out[1..], b"secret");
///
/// // Returned under `Protected`, so it is wiped when the caller drops it.
/// let kept = Protected::new(out);
/// assert_eq!(kept.risky_ref().len(), 7);
/// ```
#[derive(Default)]
pub struct Buffer(Vec<u8>);

/// The smallest allocation a growing `Buffer` makes.
const LEAST: usize = 64;

impl Buffer {
    /// An empty buffer that allocates nothing until a byte is written.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// An empty buffer with room for `capacity` bytes before it grows.
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// The bytes written so far.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes fit before the buffer grows.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Make room for `additional` more bytes.
    ///
    /// A buffer with the room already is left alone. Otherwise its bytes
    /// are copied into a fresh allocation, and the old one is wiped before
    /// it is freed. The new allocation doubles the length, so a buffer
    /// that grows byte by byte still grows in a bounded number of steps,
    /// and never balloons a buffer that had room.
    ///
    /// The check is inlined into the writer, as `Vec`'s own is, so a byte
    /// costs a compare; only the growth is a call.
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        if self.0.capacity() - self.0.len() < additional {
            self.grow(additional);
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, additional: usize) {
        let capacity = self
            .0
            .len()
            .saturating_add(additional)
            .max(self.0.len().saturating_mul(2))
            .max(LEAST);
        let mut grown = Vec::with_capacity(capacity);
        grown.extend_from_slice(&self.0);
        wipe_vec(&mut self.0);
        self.0 = grown;
    }

    /// Append one byte.
    #[inline]
    pub fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.0.push(byte);
    }

    /// Append `bytes`.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    /// Wipe every byte and keep the allocation, for writing into again.
    pub fn clear(&mut self) {
        wipe_vec(&mut self.0);
    }

    /// Take the bytes as a `Vec<u8>`, and with them the duty to wipe it:
    /// the `Vec` is freed unwiped unless its new owner wipes it, and if it
    /// grows it leaves its old bytes behind. For handing bytes to an API
    /// that takes a `Vec`, right before they are used.
    pub fn risky_into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for Buffer {
    /// Take over `bytes`. Any allocation the `Vec` outgrew before this is
    /// already gone, unwiped; from here on the buffer's rules apply.
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for Buffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Buffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for Buffer {
    /// Wipe every byte, held or spare, and release the allocation, so the
    /// drop that follows has nothing left to wipe.
    fn zeroize(&mut self) {
        wipe_vec(&mut self.0);
        self.0 = Vec::new();
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Buffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_back_through_the_slice() {
        let mut out = Buffer::new();
        out.push(1);
        out.extend_from_slice(&[2, 3]);
        assert_eq!(&*out, &[1, 2, 3]);
        assert_eq!(out.as_slice(), &[1, 2, 3]);
        assert_eq!(out.len(), 3);
        out[0] = 9;
        assert_eq!(&*out, &[9, 2, 3], "bytes are patched in place");
    }

    #[test]
    fn growth_moves_to_a_bigger_allocation_and_keeps_the_bytes() {
        let mut out = Buffer::with_capacity(4);
        out.extend_from_slice(&[1, 2, 3, 4]);
        let before = out.as_slice().as_ptr();
        out.push(5);
        assert!(
            !core::ptr::eq(out.as_slice().as_ptr(), before),
            "a full buffer grows into a fresh allocation"
        );
        assert_eq!(&*out, &[1, 2, 3, 4, 5]);
        assert!(
            out.capacity() >= LEAST,
            "the first growth is at least {LEAST}"
        );

        let mut big = Buffer::with_capacity(100);
        big.extend_from_slice(&[7; 100]);
        big.reserve(1);
        assert!(big.capacity() >= 200, "a buffer doubles its length");

        let before = big.as_slice().as_ptr();
        big.reserve(10);
        assert!(
            core::ptr::eq(big.as_slice().as_ptr(), before),
            "a buffer with room does not move"
        );
    }

    #[test]
    fn clear_wipes_and_keeps_the_allocation() {
        let mut out = Buffer::with_capacity(16);
        out.extend_from_slice(b"secret");
        let before = out.as_slice().as_ptr();
        out.clear();
        assert!(out.is_empty());
        assert!(core::ptr::eq(out.as_slice().as_ptr(), before));
        assert_eq!(out.capacity(), 16);
    }

    #[test]
    fn zeroize_wipes_and_releases_the_allocation() {
        let mut out = Buffer::with_capacity(16);
        out.extend_from_slice(b"secret");
        out.zeroize();
        assert!(out.is_empty());
        assert_eq!(out.capacity(), 0, "nothing is left for the drop to wipe");
    }

    #[test]
    fn a_vec_moves_in_and_out() {
        let out = Buffer::from(vec![1u8, 2]);
        assert_eq!(&*out, &[1, 2]);
        assert_eq!(out.risky_into_vec(), vec![1, 2]);
    }
}
