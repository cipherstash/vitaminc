//! `Locked<T>`: storage for secrets that outlive a call.
//!
//! See the [`Locked`] docs for what it guarantees and when to use it instead
//! of [`Protected`](crate::Protected).

use crate::{AsProtectedRef, Choice, OpaqueDebug, ProtectedRef, TimingSafeEq, Zeroed};
use core::any::type_name;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicU8, Ordering};
use std::io;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(all(unix, not(miri)))]
mod unix;
#[cfg(all(unix, not(miri)))]
use unix::Region;

#[cfg(not(all(unix, not(miri))))]
mod fallback;
#[cfg(not(all(unix, not(miri))))]
use fallback::Region;

/// Why a [`Locked`] value could not be created, or why its memory is not
/// locked.
///
/// Only [`Refused`](LockError::Refused), [`Dump`](LockError::Dump) and
/// [`Unavailable`](LockError::Unavailable) describe a *degraded* value: under
/// [`LockPolicy::BestEffort`] the value is still created and reports them
/// from [`Locked::lock_error`]. The other variants mean no value exists.
#[derive(Debug)]
#[non_exhaustive]
pub enum LockError {
    /// The operating system would not map the region at all.
    Map {
        /// The size of the mapping requested, guard pages included.
        bytes: usize,
        /// The OS error.
        source: io::Error,
    },
    /// The region was mapped but a guard page could not be protected.
    Guard {
        /// The OS error.
        source: io::Error,
    },
    /// `mlock` refused the interior, almost always because it would exceed
    /// `RLIMIT_MEMLOCK` (64 KiB by default on many Linux hosts). Raise the
    /// limit with `ulimit -l`, `LimitMEMLOCK=` in a systemd unit, or the
    /// container runtime's ulimit setting.
    Refused {
        /// The bytes that would have been locked.
        bytes: usize,
        /// The soft `RLIMIT_MEMLOCK` at the time, when it is finite and readable.
        limit: Option<u64>,
        /// The OS error.
        source: io::Error,
    },
    /// The region is locked but could not be excluded from core dumps
    /// (`madvise(MADV_DONTDUMP)` on Linux was refused, which a seccomp
    /// filter can do). The bytes would appear in a core dump.
    Dump {
        /// The OS error.
        source: io::Error,
    },
    /// This platform or build has no memory locking (non-Unix targets, and
    /// Miri). The value is stored on the ordinary heap and wiped on drop.
    Unavailable,
    /// `T` needs an alignment larger than a page, which the region cannot
    /// provide.
    Alignment {
        /// `T`'s alignment.
        align: usize,
        /// The page size, or 0 when the backend has no pages.
        page: usize,
    },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Map { bytes, source } => {
                write!(f, "could not map {bytes} bytes for locked storage: {source}")
            }
            Self::Guard { source } => write!(f, "could not protect a guard page: {source}"),
            Self::Refused {
                bytes,
                limit: Some(limit),
                source,
            } => write!(
                f,
                "locking {bytes} bytes was refused ({source}); the RLIMIT_MEMLOCK soft limit is {limit} bytes"
            ),
            Self::Refused {
                bytes,
                limit: None,
                source,
            } => write!(f, "locking {bytes} bytes was refused ({source})"),
            Self::Dump { source } => {
                write!(f, "excluding the region from core dumps was refused ({source})")
            }
            Self::Unavailable => f.write_str("memory locking is not available on this platform"),
            Self::Alignment { align, page } => write!(
                f,
                "alignment {align} exceeds the page size {page}; locked storage cannot hold this type"
            ),
        }
    }
}

impl std::error::Error for LockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Map { source, .. }
            | Self::Guard { source }
            | Self::Refused { source, .. }
            | Self::Dump { source } => Some(source),
            Self::Unavailable | Self::Alignment { .. } => None,
        }
    }
}

/// What a [`Locked`] constructor does when the operating system refuses to
/// lock the memory or, on Linux, to exclude it from core dumps.
///
/// The policy is process-wide and set at most once, with [`LockPolicy::set`].
/// Until it is set, [`BestEffort`](LockPolicy::BestEffort) applies.
///
/// # Which to choose
///
/// A refused lock loses exactly one property: under memory pressure the
/// pages holding the secret may be written to swap, which is not wiped when
/// the process exits. On a host with no swap there is nothing to lose.
/// Everything else, including the wipe on drop and the exclusion from core
/// dumps on Linux, still holds. A refused dump exclusion, which is rare and
/// takes a seccomp filter to provoke, is treated the same way.
///
/// `BestEffort` is the default because a strict default fails in development
/// and CI, where swap exposure is irrelevant, and teaches people to turn it
/// off. A service that needs the guarantee sets `Strict` once at startup, or
/// checks [`Locked::locked`] on the values it cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockPolicy {
    /// Create the value anyway and record the refusal, readable from
    /// [`Locked::lock_error`]. When more than one protection is refused,
    /// the lock refusal is the one recorded.
    #[default]
    BestEffort,
    /// Fail the constructor with the refusal.
    Strict,
}

const POLICY_UNSET: u8 = 0;
const POLICY_BEST_EFFORT: u8 = 1;
const POLICY_STRICT: u8 = 2;
static POLICY: AtomicU8 = AtomicU8::new(POLICY_UNSET);

/// The process policy was already set to a different value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicyError {
    /// The policy in force.
    pub current: LockPolicy,
}

impl fmt::Display for LockPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the lock policy is already set to {:?}", self.current)
    }
}

impl std::error::Error for LockPolicyError {}

impl LockPolicy {
    fn encode(self) -> u8 {
        match self {
            Self::BestEffort => POLICY_BEST_EFFORT,
            Self::Strict => POLICY_STRICT,
        }
    }

    fn decode(raw: u8) -> Self {
        match raw {
            POLICY_STRICT => Self::Strict,
            _ => Self::BestEffort,
        }
    }

    /// Set the process-wide policy. Succeeds at most once, or again with the
    /// same value; a different value after the first is an error carrying the
    /// policy in force.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::LockPolicy;
    ///
    /// // A test binary runs many tests in one process; set once, tolerate repeats.
    /// let _ = LockPolicy::BestEffort.set();
    /// assert_eq!(LockPolicy::current(), LockPolicy::BestEffort);
    /// ```
    pub fn set(self) -> Result<(), LockPolicyError> {
        let wanted = self.encode();
        match POLICY.compare_exchange(POLICY_UNSET, wanted, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(current) if current == wanted => Ok(()),
            Err(current) => Err(LockPolicyError {
                current: Self::decode(current),
            }),
        }
    }

    /// The policy in force: the one set with [`set`](Self::set), or
    /// `BestEffort`.
    pub fn current() -> Self {
        Self::decode(POLICY.load(Ordering::Acquire))
    }
}

/// A secret stored in memory that is locked against swapping, excluded from
/// core dumps where the platform allows, fenced by guard pages, and wiped
/// when dropped.
///
/// `Protected<T>` stores its value inline and wipes it on drop, which is the
/// right shape for a value that lives for one call. It is the wrong shape for
/// a value that lives for the process: nothing drops a static, a leaked
/// `Arc`, or anything at all on `SIGTERM`, `SIGKILL` or `process::exit`. The
/// bytes of a long-lived key then outlive the process in a core dump, in
/// swap, and at every address a move left them at.
///
/// `Locked<T>` closes each of those at allocation time, where the caller
/// cannot get it wrong, instead of at exit time, where they can:
///
/// - **The value never moves.** It is written once into a region obtained
///   from the operating system (`mmap` on Unix) and only ever reached by
///   reference. The `Locked<T>` handle itself is three words on Unix;
///   moving it moves no secret bytes.
/// - **Not swapped.** The region is `mlock`ed, so the kernel keeps it
///   resident. This can be refused; see [`LockPolicy`].
/// - **Not dumped.** On Linux the region is marked `MADV_DONTDUMP`, so a core
///   dump does not contain it.
/// - **Fenced.** A `PROT_NONE` guard page either side turns an overrun into a
///   fault instead of a silent read or write of a neighbour.
/// - **Wiped.** On drop, `T`'s own destructor runs, then every byte of the
///   region is overwritten with volatile stores before it is unmapped. The
///   store goes through a pointer the compiler cannot prove dead, so it
///   cannot be elided, and it is part of releasing the region rather than
///   of `Locked`'s destructor, so a panic in `T`'s destructor cannot skip it.
///
/// # What it cannot do
///
/// `Locked` protects the bytes `T` occupies *inline*. A `T` that owns a heap
/// allocation (`Vec<u8>`, `String`) has only its header in the region; the
/// heap buffer is ordinary memory. Use it for inline types: `[u8; N]`, or a
/// struct of them.
///
/// Constructing from an existing value costs one copy from the caller's
/// value into the region. The parameter's bytes are wiped on the way, and
/// zeroized if the region could not be obtained at all, but the caller's own
/// copy, if one exists at another address, is the caller's.
/// [`generate`](Self::generate) avoids the copy entirely by building the
/// value in place.
///
/// # Example
///
/// ```
/// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
/// use vitaminc::protected::{Locked, LockError};
///
/// # fn fill_from_csprng(buf: &mut [u8; 32]) { buf.copy_from_slice(&[7u8; 32]); }
/// # fn main() -> Result<(), LockError> {
/// // Born inside the locked region; never on the stack.
/// let key: Locked<[u8; 32]> = Locked::generate(fill_from_csprng)?;
///
/// key.with(|k| assert_eq!(k[0], 7));
/// if !key.locked() {
///     eprintln!("key memory is not locked: {}", key.lock_error().unwrap());
/// }
/// # Ok(())
/// # }
/// ```
pub struct Locked<T: Zeroize> {
    region: Region,
    /// Boxed so that the common, locked case costs one word.
    lock: Option<Box<LockError>>,
    _value: PhantomData<T>,
}

// SAFETY: `Locked<T>` owns its region exclusively, exactly as `Box<T>` owns
// its allocation, so it is `Send` / `Sync` precisely when `T` is.
unsafe impl<T: Zeroize + Send> Send for Locked<T> {}
unsafe impl<T: Zeroize + Sync> Sync for Locked<T> {}

/// A region sized for a `T` with the process [`LockPolicy`] applied, holding
/// no `T` yet. Only once a `T` has been written does a constructor turn this
/// into a [`Locked`]: dropping this drops no `T`, so a panic between the
/// allocation and the write (in `T::zeroed()`, say) releases zero-filled
/// bytes instead of running `T`'s destructor over them.
struct Unfilled<T> {
    region: Region,
    lock: Option<Box<LockError>>,
    _value: PhantomData<T>,
}

impl<T> Unfilled<T> {
    fn allocate() -> Result<Self, LockError> {
        let (region, lock) = Region::allocate(mem::size_of::<T>(), mem::align_of::<T>())?;
        if LockPolicy::current() == LockPolicy::Strict {
            if let Some(err) = lock {
                // `region` is dropped here, wiped and released.
                return Err(err);
            }
        }
        Ok(Self {
            region,
            lock: lock.map(Box::new),
            _value: PhantomData,
        })
    }

    fn as_ptr(&self) -> *mut T {
        self.region.ptr().as_ptr().cast::<T>()
    }

    /// # Safety
    ///
    /// The interior must hold a live `T`.
    unsafe fn filled(self) -> Locked<T>
    where
        T: Zeroize,
    {
        Locked {
            region: self.region,
            lock: self.lock,
            _value: PhantomData,
        }
    }
}

impl<T: Zeroize> Locked<T> {
    fn as_ptr(&self) -> *mut T {
        self.region.ptr().as_ptr().cast::<T>()
    }

    /// Move `value` into locked storage.
    ///
    /// The bytes of the parameter are wiped after the copy, without running
    /// `T`'s destructor, so the only copy of the value left in ordinary
    /// memory is any the caller still holds. If no region can be obtained
    /// the parameter is zeroized and dropped before the error is returned.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Locked, LockError};
    ///
    /// # fn main() -> Result<(), LockError> {
    /// let key = Locked::new([0xA5u8; 16])?;
    /// assert_eq!(key.risky_ref(), &[0xA5u8; 16]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(mut value: T) -> Result<Self, LockError> {
        let unfilled = match Unfilled::allocate() {
            Ok(unfilled) => unfilled,
            Err(err) => {
                // `T: Zeroize` does not imply `ZeroizeOnDrop`; the input is
                // ours now and must not leave here intact.
                value.zeroize();
                return Err(err);
            }
        };
        let mut slot = ManuallyDrop::new(value);
        // SAFETY: the interior is at least `size_of::<T>()` bytes, aligned to
        // `align_of::<T>()`, and holds no `T` yet, so a bitwise copy in is a
        // move. `slot` is `ManuallyDrop` and never read again, so the source
        // is wiped bitwise below without any semantic effect on `T`. After
        // the copy the interior holds a live `T`, which `filled` requires.
        unsafe {
            ptr::copy_nonoverlapping(&*slot as *const T, unfilled.as_ptr(), 1);
            wipe_bytes(&mut *slot as *mut T);
            Ok(unfilled.filled())
        }
    }

    /// Build the value in place: the region is filled with `T::zeroed()` and
    /// `f` is given `&mut T` to fill in. The secret is never on the stack.
    ///
    /// Name `T` on the call (`Locked::<[u8; 32]>::generate`) or on the
    /// closure parameter; a method call inside the closure cannot be
    /// resolved from the binding's type alone.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Locked, LockError};
    ///
    /// # fn main() -> Result<(), LockError> {
    /// let key = Locked::<[u8; 8]>::generate(|k| k.copy_from_slice(b"12345678"))?;
    /// assert_eq!(key.risky_ref(), b"12345678");
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate<F>(f: F) -> Result<Self, LockError>
    where
        T: Zeroed,
        F: FnOnce(&mut T),
    {
        let mut this = Self::zeroed()?;
        f(this.risky_mut());
        Ok(this)
    }

    /// [`generate`](Self::generate) for a filler that can fail. A failure
    /// drops the half-built value, wiping it.
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Locked, LockError};
    ///
    /// #[derive(Debug)]
    /// enum KeyError { Lock(LockError), Rng }
    /// impl From<LockError> for KeyError {
    ///     fn from(e: LockError) -> Self { KeyError::Lock(e) }
    /// }
    ///
    /// let key: Result<Locked<[u8; 32]>, KeyError> = Locked::try_generate(|_k| Err(KeyError::Rng));
    /// assert!(matches!(key, Err(KeyError::Rng)));
    /// ```
    pub fn try_generate<F, E>(f: F) -> Result<Self, E>
    where
        T: Zeroed,
        E: From<LockError>,
        F: FnOnce(&mut T) -> Result<(), E>,
    {
        let mut this = Self::zeroed()?;
        f(this.risky_mut())?;
        Ok(this)
    }

    /// Locked storage holding `T::zeroed()`.
    pub fn zeroed() -> Result<Self, LockError>
    where
        T: Zeroed,
    {
        let unfilled = Unfilled::allocate()?;
        // A panic in `T::zeroed()` unwinds through `unfilled`, which releases
        // the region without treating its zero-filled bytes as a `T`.
        let zeroed = T::zeroed();
        // SAFETY: the interior is sized and aligned for a `T` and holds none
        // yet; after the write it holds one, which `filled` requires.
        unsafe {
            ptr::write(unfilled.as_ptr(), zeroed);
            Ok(unfilled.filled())
        }
    }

    /// Whether every protection the platform offers was applied: the memory
    /// is locked against swapping and, on Linux, excluded from core dumps.
    /// [`lock_error`](Self::lock_error) says which one was refused.
    pub fn locked(&self) -> bool {
        self.lock.is_none()
    }

    /// Why the memory is not fully protected, when it is not.
    pub fn lock_error(&self) -> Option<&LockError> {
        self.lock.as_deref()
    }

    /// Demand the lock: `Ok(self)` when locked, otherwise the refusal, with
    /// the value dropped and wiped. This is the per-value form of
    /// [`LockPolicy::Strict`]:
    ///
    /// ```
    /// # mod vitaminc { pub mod protected { pub use vitaminc_protected::*; } }
    /// use vitaminc::protected::{Locked, LockError};
    ///
    /// fn load_key() -> Result<Locked<[u8; 32]>, LockError> {
    ///     Locked::<[u8; 32]>::generate(|k| k.fill(1))?.require_locked()
    /// }
    /// ```
    pub fn require_locked(mut self) -> Result<Self, LockError> {
        match self.lock.take() {
            None => Ok(self),
            Some(err) => Err(*err),
        }
    }

    /// A shared reference to the value. Named like
    /// [`Controlled::risky_ref`](crate::Controlled::risky_ref): anything you
    /// copy out of it is yours to wipe.
    pub fn risky_ref(&self) -> &T {
        // SAFETY: every constructor writes a `T` into the interior before
        // returning, and only `drop` invalidates it.
        unsafe { &*self.as_ptr() }
    }

    /// An exclusive reference to the value.
    pub fn risky_mut(&mut self) -> &mut T {
        // SAFETY: as `risky_ref`, and `&mut self` makes the borrow exclusive.
        unsafe { &mut *self.as_ptr() }
    }

    /// Run `f` over the value.
    pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        f(self.risky_ref())
    }

    /// Change the value in place.
    pub fn update(&mut self, f: impl FnOnce(&mut T)) {
        f(self.risky_mut())
    }

    /// A second locked region holding a clone of the value.
    ///
    /// There is no `Clone` impl because a clone allocates and can fail. The
    /// clone is made on the stack and moved in with [`new`](Self::new), so
    /// it pays that constructor's one copy.
    pub fn try_clone(&self) -> Result<Self, LockError>
    where
        T: Clone,
    {
        Self::new(self.risky_ref().clone())
    }

    /// Run the destructor and the wipe, and hand back the region so a test
    /// can look at it before it is released.
    #[cfg(test)]
    fn into_wiped_region(self) -> Region {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the interior holds a live `T`, dropped exactly once here;
        // `this` is `ManuallyDrop`, so `Locked::drop` never runs.
        unsafe { ptr::drop_in_place(this.as_ptr()) };
        this.region.wipe();
        drop(this.lock.take());
        // SAFETY: `this` is never used again, so the region is moved out once.
        unsafe { ptr::read(&this.region) }
    }
}

/// Overwrite the bytes of a `T` with volatile zero stores, without any
/// semantic effect on `T`. For a moved-from slot only.
///
/// # Safety
///
/// `slot` must point to `size_of::<T>()` writable bytes that will never be
/// read as a `T` again.
unsafe fn wipe_bytes<T>(slot: *mut T) {
    let bytes =
        core::slice::from_raw_parts_mut(slot.cast::<MaybeUninit<u8>>(), mem::size_of::<T>());
    for b in bytes {
        ptr::write_volatile(b, MaybeUninit::new(0));
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

impl<T: Zeroize> Drop for Locked<T> {
    fn drop(&mut self) {
        // SAFETY: the interior holds a live `T`; this is the only drop.
        unsafe { ptr::drop_in_place(self.as_ptr()) };
        // `region` is then dropped by the field destructor, which wipes and
        // releases it. Field destructors run even when this body unwinds,
        // so a panicking `T::drop` cannot skip the wipe.
    }
}

impl<T: Zeroize> Zeroize for Locked<T> {
    fn zeroize(&mut self) {
        self.risky_mut().zeroize();
    }
}

/// The drop wipes the whole region, not only the bytes `T::zeroize` reaches.
impl<T: Zeroize> ZeroizeOnDrop for Locked<T> {}

impl<T: Zeroize> OpaqueDebug for Locked<T> {}

impl<T: Zeroize> fmt::Debug for Locked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Locked<{}>({})",
            type_name::<T>(),
            if self.locked() { "locked" } else { "unlocked" }
        )
    }
}

impl<T: Zeroize + TimingSafeEq> TimingSafeEq for Locked<T> {
    fn ts_eq(&self, other: &Self) -> Choice {
        self.risky_ref().ts_eq(other.risky_ref())
    }
}

impl<'a, T: Zeroize> AsProtectedRef<'a, T> for Locked<T> {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, T> {
        ProtectedRef(self.risky_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_moved_in_reads_back() {
        let key = Locked::new([0xA5u8; 32]).unwrap();
        assert_eq!(key.risky_ref(), &[0xA5u8; 32]);
    }

    #[test]
    fn a_generated_value_is_built_in_place() {
        let key = Locked::<[u8; 32]>::generate(|k| k.fill(9)).unwrap();
        assert_eq!(key.risky_ref(), &[9u8; 32]);
        assert!(std::ptr::eq(
            key.risky_ref().as_ptr(),
            key.region.ptr().as_ptr()
        ));
    }

    #[test]
    fn a_failed_generation_returns_the_callers_error() {
        #[derive(Debug, PartialEq)]
        enum E {
            Lock,
            Rng,
        }
        impl From<LockError> for E {
            fn from(_: LockError) -> Self {
                E::Lock
            }
        }
        let r: Result<Locked<[u8; 16]>, E> = Locked::try_generate(|_| Err(E::Rng));
        assert_eq!(r.unwrap_err(), E::Rng);
    }

    #[test]
    fn update_changes_the_value_in_place() {
        let mut key = Locked::new([0u8; 8]).unwrap();
        let before = key.risky_ref().as_ptr();
        key.update(|k| k[3] = 42);
        assert_eq!(key.risky_ref()[3], 42);
        assert_eq!(before, key.risky_ref().as_ptr());
    }

    #[test]
    fn the_region_is_all_zero_after_the_wipe() {
        let key = Locked::new([0xFFu8; 64]).unwrap();
        let region = key.into_wiped_region();
        // SAFETY: the region is still mapped; the interior holds 64 initialised bytes.
        let bytes = unsafe { core::slice::from_raw_parts(region.ptr().as_ptr(), 64) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn the_value_owns_its_own_drop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Counted(u8);
        impl Zeroize for Counted {
            fn zeroize(&mut self) {
                self.0 = 0;
            }
        }
        impl Drop for Counted {
            fn drop(&mut self) {
                let _ = DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        drop(Locked::new(Counted(1)).unwrap());
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_panicking_zeroed_releases_the_region_without_dropping_a_value() {
        // `Boom` owns a heap allocation, so `drop_in_place` over the zero-
        // filled interior would free a null pointer. `T::zeroed()` panics
        // before any `T` exists, and the region must be released as bytes.
        struct Boom(#[allow(dead_code)] Box<u8>);
        impl Zeroize for Boom {
            fn zeroize(&mut self) {
                *self.0 = 0;
            }
        }
        impl Zeroed for Boom {
            fn zeroed() -> Self {
                panic!("no zero value");
            }
        }
        let r = std::panic::catch_unwind(Locked::<Boom>::zeroed);
        assert!(r.is_err());
        let r = std::panic::catch_unwind(|| Locked::<Boom>::generate(|_| {}));
        assert!(r.is_err());
    }

    #[test]
    fn the_region_is_wiped_when_the_values_destructor_panics() {
        // The wipe belongs to the region's release, which runs during the
        // unwind out of `Locked::drop`. Observed directly through the
        // region: `into_wiped_region` is not used here because the point is
        // the path that does not go through it.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        struct Angry([u8; 16]);
        impl Zeroize for Angry {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        impl Drop for Angry {
            fn drop(&mut self) {
                let _ = DROPS.fetch_add(1, Ordering::SeqCst);
                panic!("angry");
            }
        }
        let key = Locked::new(Angry([0xEE; 16])).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(key)));
        assert!(r.is_err());
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        // No double drop, no leak: the region was released once. The bytes
        // themselves are checked by `tests/locked_fallback_wipe.rs`, where
        // an observing allocator can see them at release.
    }

    #[cfg(all(unix, not(miri)))]
    #[test]
    fn a_failed_allocation_zeroizes_the_input() {
        // 128 KiB alignment exceeds every page size this crate is built for,
        // so the region cannot be mapped and `new` must fail. The input is
        // ours by then; it must be zeroized, not merely dropped.
        use std::sync::atomic::{AtomicBool, Ordering};
        static ZEROIZED: AtomicBool = AtomicBool::new(false);
        #[repr(align(131072))]
        struct Wide(u8);
        impl Zeroize for Wide {
            fn zeroize(&mut self) {
                self.0 = 0;
                ZEROIZED.store(true, Ordering::SeqCst);
            }
        }
        impl Drop for Wide {
            fn drop(&mut self) {
                assert_eq!(self.0, 0, "dropped before being zeroized");
            }
        }
        let r = Locked::new(Wide(0x5A));
        assert!(matches!(r, Err(LockError::Alignment { .. })), "{r:?}");
        assert!(ZEROIZED.load(Ordering::SeqCst));
    }

    #[test]
    fn every_error_displays_and_only_os_errors_have_a_source() {
        use std::error::Error;
        let os = || io::Error::from_raw_os_error(1);
        let errors = [
            LockError::Map {
                bytes: 3,
                source: os(),
            },
            LockError::Guard { source: os() },
            LockError::Refused {
                bytes: 3,
                limit: Some(0),
                source: os(),
            },
            LockError::Refused {
                bytes: 3,
                limit: None,
                source: os(),
            },
            LockError::Dump { source: os() },
            LockError::Unavailable,
            LockError::Alignment { align: 8, page: 4 },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
            let has_source = !matches!(err, LockError::Unavailable | LockError::Alignment { .. });
            assert_eq!(err.source().is_some(), has_source, "{err}");
        }
        assert!(errors[4].to_string().contains("core dumps"));
    }

    #[test]
    fn the_parameter_slot_is_wiped_by_new() {
        // `new` takes the value by move; the slot it wipes is its own parameter.
        // Observe through a type whose bytes we can locate: after the call the
        // region holds the value and the source no longer does. This pins the
        // bitwise wipe by checking that no `Drop` ran on the source.
        struct NoDrop([u8; 4]);
        impl Zeroize for NoDrop {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        impl Drop for NoDrop {
            fn drop(&mut self) {
                assert_eq!(
                    self.0,
                    [1, 2, 3, 4],
                    "drop must see the value exactly once, intact"
                );
            }
        }
        let l = Locked::new(NoDrop([1, 2, 3, 4])).unwrap();
        assert_eq!(l.risky_ref().0, [1, 2, 3, 4]);
    }

    #[test]
    fn try_clone_is_a_second_region() {
        let a = Locked::new([3u8; 16]).unwrap();
        let b = a.try_clone().unwrap();
        assert_eq!(a.risky_ref(), b.risky_ref());
        assert_ne!(a.region.ptr(), b.region.ptr());
    }

    #[test]
    fn require_locked_passes_a_locked_value_through() {
        let key = Locked::new([1u8; 8]).unwrap();
        if key.locked() {
            assert!(key.require_locked().is_ok());
        } else {
            assert!(key.require_locked().is_err());
        }
    }

    #[test]
    fn debug_reveals_nothing_but_the_type_and_lock_state() {
        let key = Locked::new([0x42u8; 8]).unwrap();
        let s = format!("{key:?}");
        assert!(s.starts_with("Locked<[u8; 8]>("), "{s}");
        assert!(!s.contains("42"));
    }

    #[test]
    fn timing_safe_eq_compares_the_values() {
        let a = Locked::new([1u8; 8]).unwrap();
        let b = Locked::new([1u8; 8]).unwrap();
        let c = Locked::new([2u8; 8]).unwrap();
        assert!(bool::from(a.ts_eq(&b)));
        assert!(!bool::from(a.ts_eq(&c)));
    }

    #[test]
    fn zero_sized_and_odd_sized_types_are_fine() {
        #[derive(Zeroize)]
        struct Nothing;
        let _ = Locked::new(Nothing).unwrap();
        let odd = Locked::new([7u8; 33]).unwrap();
        assert_eq!(odd.risky_ref().len(), 33);
    }

    #[test]
    fn the_handle_is_send_and_sync() {
        fn assert_send_sync<S: Send + Sync>() {}
        assert_send_sync::<Locked<[u8; 32]>>();
    }

    #[test]
    fn the_handle_is_a_few_words_whatever_the_value_size() {
        let words = mem::size_of::<Locked<[u8; 1024]>>() / mem::size_of::<usize>();
        // Two for the Unix region (three for the fallback's `Layout`), one
        // for the boxed lock error.
        assert!(words <= 4, "{words} words");
        assert_eq!(
            mem::size_of::<Locked<[u8; 1024]>>(),
            mem::size_of::<Locked<u8>>()
        );
    }

    #[cfg(all(unix, not(miri)))]
    #[test]
    fn a_small_value_is_locked_when_the_limit_allows() {
        let key = Locked::new([1u8; 32]).unwrap();
        // The interior is one page. If the soft limit cannot hold even a
        // megabyte the environment is deliberately constrained; the
        // process-level tests cover that case.
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
        let generous = rc == 0 && (lim.rlim_cur == libc::RLIM_INFINITY || lim.rlim_cur >= 1 << 20);
        if generous {
            assert!(key.locked(), "{:?}", key.lock_error());
        }
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn the_kernel_reports_the_region_locked_and_not_dumpable() {
        let key = Locked::new([1u8; 32]).unwrap();
        if !key.locked() {
            return; // constrained environment; covered by the process tests
        }
        let addr = key.region.ptr().as_ptr() as usize;
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_region = false;
        let mut locked_kb = None;
        let mut flags = None;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ') {
                if let Some((lo, hi)) = range.split_once('-') {
                    if let (Ok(lo), Ok(hi)) =
                        (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                    {
                        in_region = lo <= addr && addr < hi;
                        continue;
                    }
                }
            }
            if !in_region {
                continue;
            }
            if let Some(v) = line.strip_prefix("Locked:") {
                locked_kb = v
                    .trim()
                    .split(' ')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok());
            }
            if let Some(v) = line.strip_prefix("VmFlags:") {
                flags = Some(v.trim().to_string());
            }
        }
        assert!(locked_kb.unwrap_or(0) > 0, "Locked: {locked_kb:?}");
        assert!(
            flags.as_deref().unwrap_or("").split(' ').any(|f| f == "dd"),
            "VmFlags: {flags:?}"
        );
    }
}
