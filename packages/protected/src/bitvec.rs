use crate::Protected;
use bitvec::prelude::{BitOrder, BitStore};
use bitvec::{
    ptr::{BitRef, Const, Mut},
    slice::{BitSlice, BitSliceIndex},
};

// TODO: Implement for all Paranoid<Inner = usize> types or all types at least
impl<'a, T, O> BitSliceIndex<'a, T, O> for Protected<usize>
where
    T: BitStore,
    O: BitOrder,
{
    type Immut = BitRef<'a, Const, T, O>;
    type Mut = BitRef<'a, Mut, T, O>;

    #[inline]
    fn get(self, bits: &'a BitSlice<T, O>) -> Option<Self::Immut> {
        // TODO: This should be a constant time check?
        if self.0 < bits.len() {
            Some(unsafe { self.get_unchecked(bits) })
        } else {
            None
        }
    }

    #[inline]
    fn get_mut(self, bits: &'a mut BitSlice<T, O>) -> Option<Self::Mut> {
        if self.0 < bits.len() {
            Some(unsafe { self.get_unchecked_mut(bits) })
        } else {
            None
        }
    }

    #[inline]
    unsafe fn get_unchecked(self, bits: &'a BitSlice<T, O>) -> Self::Immut {
        bits.as_bitptr().add(self.0).as_ref().unwrap()
    }

    #[inline]
    unsafe fn get_unchecked_mut(self, bits: &'a mut BitSlice<T, O>) -> Self::Mut {
        bits.as_mut_bitptr().add(self.0).as_mut().unwrap()
    }

    #[inline]
    fn index(self, bits: &'a BitSlice<T, O>) -> Self::Immut {
        self.0
            .get(bits)
            .unwrap_or_else(|| panic!("index {:?} out of bounds: {}", self.0, bits.len()))
    }

    #[inline]
    fn index_mut(self, bits: &'a mut BitSlice<T, O>) -> Self::Mut {
        let len = bits.len();
        self.0
            .get_mut(bits)
            .unwrap_or_else(|| panic!("index {:?} out of bounds: {}", self.0, len))
    }
}

impl<'a, T, O> BitSliceIndex<'a, T, O> for Protected<u8>
where
    T: BitStore,
    O: BitOrder,
{
    type Immut = BitRef<'a, Const, T, O>;
    type Mut = BitRef<'a, Mut, T, O>;

    #[inline]
    fn get(self, bits: &'a BitSlice<T, O>) -> Option<Self::Immut> {
        // TODO: This should be a constant time check?
        if (self.0 as usize) < bits.len() {
            Some(unsafe { self.get_unchecked(bits) })
        } else {
            None
        }
    }

    #[inline]
    fn get_mut(self, bits: &'a mut BitSlice<T, O>) -> Option<Self::Mut> {
        if (self.0 as usize) < bits.len() {
            Some(unsafe { self.get_unchecked_mut(bits) })
        } else {
            None
        }
    }

    #[inline]
    unsafe fn get_unchecked(self, bits: &'a BitSlice<T, O>) -> Self::Immut {
        bits.as_bitptr().add(self.0 as usize).as_ref().unwrap()
    }

    #[inline]
    unsafe fn get_unchecked_mut(self, bits: &'a mut BitSlice<T, O>) -> Self::Mut {
        bits.as_mut_bitptr().add(self.0 as usize).as_mut().unwrap()
    }

    #[inline]
    fn index(self, bits: &'a BitSlice<T, O>) -> Self::Immut {
        (self.0 as usize)
            .get(bits)
            .unwrap_or_else(|| panic!("index {:?} out of bounds: {}", self.0, bits.len()))
    }

    #[inline]
    fn index_mut(self, bits: &'a mut BitSlice<T, O>) -> Self::Mut {
        let len = bits.len();
        (self.0 as usize)
            .get_mut(bits)
            .unwrap_or_else(|| panic!("index {:?} out of bounds: {}", self.0, len))
    }
}
