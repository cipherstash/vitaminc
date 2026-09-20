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

mod layout;
#[cfg(kani)]
mod proofs;

#[cfg(all(unix, not(kani)))]
mod unix;
#[cfg(all(unix, not(kani)))]
use unix::Region;

// The fallback is the backend off Unix and under Kani, which cannot execute
// system calls. It is also built into every test binary so that its own
// tests run on the platforms CI has.
#[cfg(any(test, not(unix), kani))]
mod fallback;
#[cfg(any(not(unix), kani))]
use fallback::Region;

/// Why a [`Locked`] value could not be created, or why its memory is not
/// locked.
///
/// [`Refused`](LockError::Refused), [`Dump`](LockError::Dump),
/// [`Unavailable`](LockError::Unavailable) and [`Forked`](LockError::Forked)
/// describe a *degraded* value that exists: under
/// [`LockPolicy::BestEffort`] the first three are reported by
/// [`Locked::lock_error`] from construction on, and `Forked` from the moment
/// a forked child looks. [`Locked::require_locked`] turns any of them into
/// an error and drops the value. The other variants mean no value was
/// created.
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
    /// This platform or build has no memory locking: non-Unix targets, Miri
    /// (which maps the region but cannot lock it) and Kani. The value is
    /// wiped on drop as usual.
    Unavailable,
    /// The value was created in another process. Memory locks are not
    /// inherited across `fork`, so in the child the region is unlocked
    /// until [`Locked::relock`] is called there.
    Forked,
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
            Self::Forked => f.write_str(
                "the lock belongs to the process that created the value; a forked child inherits the memory but not the lock",
            ),
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
            Self::Unavailable | Self::Forked | Self::Alignment { .. } => None,
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
/// cannot get it wrong, instead of at exit time, where they can. On Unix:
///
/// - **The value never moves.** It is written once into a region obtained
///   from the operating system with `mmap` and only ever reached by
///   reference. The `Locked<T>` handle itself is three words; moving it
///   moves no secret bytes.
/// - **Not swapped.** The region is `mlock`ed, so the kernel keeps it
///   resident. This can be refused; see [`LockPolicy`].
/// - **Not dumped.** On Linux the region is marked `MADV_DONTDUMP`, so a core
///   dump does not contain it.
/// - **Fenced.** The value sits against a `PROT_NONE` guard page, within
///   `align_of::<T>()` bytes of it, so a write past its end faults instead
///   of silently reaching a neighbour. A second guard page precedes the
///   region and catches an underrun that crosses it.
/// - **Wiped.** On drop, `T`'s own destructor runs, then every byte of the
///   region is overwritten with volatile stores before it is unmapped. The
///   store goes through a pointer the compiler cannot prove dead, so it
///   cannot be elided, and it is part of releasing the region rather than
///   of `Locked`'s destructor, so a panic in `T`'s destructor cannot skip it.
///
/// # Forking
///
/// A forked child inherits the mapping, its guard pages and, on Linux, the
/// dump exclusion, but the kernel does not carry memory locks across
/// `fork`. A `Locked` value knows which process locked it: in a child,
/// [`locked`](Self::locked) is `false`, [`lock_error`](Self::lock_error)
/// is [`LockError::Forked`] and [`require_locked`](Self::require_locked)
/// fails, until [`relock`](Self::relock) is called there. Where the choice
/// exists, create keys after forking rather than before.
///
/// # Elsewhere
///
/// On targets other than Unix, and under Kani, the value lives in an
/// ordinary heap allocation: wiped on drop exactly as above, but neither
/// locked nor fenced, and [`lock_error`](Self::lock_error) reports
/// [`LockError::Unavailable`]. Under Miri the region is mapped for real but
/// not locked or fenced, since Miri has no model for those calls.
///
/// # What it cannot do
///
/// `Locked` protects the bytes `T` occupies *inline*. A `T` that owns a heap
/// allocation (`Vec<u8>`, `String`) has only its header in the region; the
/// heap buffer is ordinary memory. Use it for inline types: `[u8; N]`, or a
/// struct of them.
///
/// Constructing from an existing value with [`new`](Self::new) copies it
/// into the region and wipes the parameter slot, but a Rust move is a
/// bitwise copy the compiler may leave behind, so a value that existed
/// before the call may survive it in ordinary memory.
/// [`generate`](Self::generate) builds the value in place and is the
/// constructor to prefer for a secret that does not yet exist.
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
        self.region
            .value_ptr(mem::size_of::<T>(), mem::align_of::<T>())
            .as_ptr()
            .cast::<T>()
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

    /// Copy the `T` in `slot` into the region, wipe `slot`'s bytes, and
    /// become a [`Locked`].
    ///
    /// # Safety
    ///
    /// `slot` must never be read as a `T` again: after this call its bytes
    /// are zero and no destructor has run on the value they held.
    unsafe fn move_in(self, slot: &mut ManuallyDrop<T>) -> Locked<T>
    where
        T: Zeroize,
    {
        // SAFETY (for the caller's contract): the interior is at least
        // `size_of::<T>()` bytes, aligned to `align_of::<T>()`, and holds no
        // `T` yet, so a bitwise copy in is a move. The source is then wiped
        // bitwise, with no semantic effect on `T` since it is never read
        // again. After the copy the interior holds a live `T`, which
        // `filled` requires.
        ptr::copy_nonoverlapping(&**slot as *const T, self.as_ptr(), 1);
        wipe_bytes(&mut **slot as *mut T);
        self.filled()
    }
}

impl<T: Zeroize> Locked<T> {
    fn as_ptr(&self) -> *mut T {
        self.region
            .value_ptr(mem::size_of::<T>(), mem::align_of::<T>())
            .as_ptr()
            .cast::<T>()
    }

    /// Move `value` into locked storage.
    ///
    /// The parameter slot is wiped after the copy, without running `T`'s
    /// destructor, and zeroized if no region could be obtained. That is
    /// the most this constructor can do: a Rust move is a bitwise copy the
    /// compiler is free to leave behind, in the caller's frame or in a
    /// spill, so a value that existed before the call may survive it in
    /// ordinary memory. [`generate`](Self::generate) is the constructor
    /// that never has the secret outside the region.
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
        // SAFETY: `slot` is this function's own parameter and is never read
        // again after the move.
        Ok(unsafe { unfilled.move_in(&mut slot) })
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

    /// Whether every protection the platform offers was applied, in this
    /// process: the memory is locked against swapping and, on Linux,
    /// excluded from core dumps. [`lock_error`](Self::lock_error) says which
    /// one was refused, or that the lock was left behind by a `fork`.
    pub fn locked(&self) -> bool {
        self.lock.is_none() && self.region.same_process()
    }

    /// Why the memory is not fully protected, when it is not.
    pub fn lock_error(&self) -> Option<&LockError> {
        static FORKED: LockError = LockError::Forked;
        self.lock
            .as_deref()
            .or_else(|| (!self.region.same_process()).then_some(&FORKED))
    }

    /// Take the lock again in the current process. For a forked child that
    /// needs a value its parent created; in any other situation it is a
    /// no-op that reports the state already known. On success the value is
    /// locked here; on refusal the reason is kept and returned, exactly as
    /// after construction under [`LockPolicy::BestEffort`].
    pub fn relock(&mut self) -> Result<(), &LockError> {
        self.lock = self.region.relock().map(Box::new);
        match self.lock.as_deref() {
            None => Ok(()),
            Some(err) => Err(err),
        }
    }

    /// Demand the lock: `Ok(self)` when locked here, otherwise the refusal
    /// (or [`LockError::Forked`] in a child that has not called
    /// [`relock`](Self::relock)), with the value dropped and wiped. This is
    /// the per-value form of [`LockPolicy::Strict`]:
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
        if !self.region.same_process() {
            return Err(LockError::Forked);
        }
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

/// Overwrite `len` bytes at `ptr` with volatile zero stores and a compiler
/// fence, so the wipe cannot be elided as a dead store. The bytes are
/// written as `MaybeUninit<u8>`, never read, so storage that holds padding
/// or a dropped value is fine.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes.
pub(super) unsafe fn wipe_raw(ptr: *mut u8, len: usize) {
    let bytes = core::slice::from_raw_parts_mut(ptr.cast::<MaybeUninit<u8>>(), len);
    for b in bytes {
        ptr::write_volatile(b, MaybeUninit::new(0));
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// [`wipe_raw`] over the bytes of a `T`, without any semantic effect on
/// `T`. For a moved-from slot only.
///
/// # Safety
///
/// `slot` must point to `size_of::<T>()` writable bytes that will never be
/// read as a `T` again.
unsafe fn wipe_bytes<T>(slot: *mut T) {
    wipe_raw(slot.cast::<u8>(), mem::size_of::<T>());
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
            key.region.value_ptr(32, 1).as_ptr()
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
        // SAFETY: the region is still mapped; the value's 64 bytes are
        // initialised, by the value and then by the wipe.
        let bytes = unsafe { core::slice::from_raw_parts(region.value_ptr(64, 1).as_ptr(), 64) };
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
        // No double drop, no leak: the region was released once. That a
        // release always wipes is checked at the region level, in
        // `fallback::tests`, where an observing allocator sees the bytes.
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
        // A 128 KiB value crosses the stack a few times on its way in and
        // out of `new`; the harness's 2 MiB thread is enough natively but
        // not with a sanitizer's redzones around every frame.
        std::thread::Builder::new()
            .stack_size(16 << 20)
            .spawn(|| {
                let r = Locked::new(Wide(0x5A));
                assert!(matches!(r, Err(LockError::Alignment { .. })), "{r:?}");
            })
            .unwrap()
            .join()
            .unwrap();
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
            LockError::Forked,
            LockError::Alignment { align: 8, page: 4 },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty());
            let has_source = !matches!(
                err,
                LockError::Unavailable | LockError::Forked | LockError::Alignment { .. }
            );
            assert_eq!(err.source().is_some(), has_source, "{err}");
        }
        assert!(errors[4].to_string().contains("core dumps"));
    }

    #[test]
    fn zeroize_clears_the_value_in_place() {
        let mut key = Locked::new([0x77u8; 24]).unwrap();
        let before = key.risky_ref().as_ptr();
        key.zeroize();
        assert_eq!(key.risky_ref(), &[0u8; 24]);
        assert_eq!(before, key.risky_ref().as_ptr());
    }

    #[test]
    fn the_policy_error_names_the_policy_in_force() {
        let err = LockPolicyError {
            current: LockPolicy::Strict,
        };
        assert_eq!(err.to_string(), "the lock policy is already set to Strict");
    }

    /// A `T` with padding. Its bytes must only ever be handled as bytes: a
    /// `u8` slice over them would claim initialisation the padding lacks.
    #[derive(Zeroize, Clone, PartialEq, Eq, Debug)]
    #[repr(C)]
    struct Padded {
        a: u8,
        b: u32,
        c: u16,
    }
    impl Zeroed for Padded {
        fn zeroed() -> Self {
            Padded { a: 0, b: 0, c: 0 }
        }
    }

    const PADDED_SIZE: usize = mem::size_of::<Padded>();
    const PADDED_ALIGN: usize = mem::align_of::<Padded>();
    const _: () = assert!(
        PADDED_SIZE > 1 + 4 + 2,
        "the type must actually have padding"
    );

    #[test]
    fn a_padded_value_moves_in_clones_generates_zeroizes_and_wipes() {
        const SIZE: usize = PADDED_SIZE;
        const ALIGN: usize = PADDED_ALIGN;

        let key = Locked::new(Padded { a: 1, b: 2, c: 3 }).unwrap();
        assert_eq!(*key.risky_ref(), Padded { a: 1, b: 2, c: 3 });
        let copy = key.try_clone().unwrap();
        assert_eq!(copy.risky_ref(), key.risky_ref());

        let mut made = Locked::<Padded>::generate(|p| p.b = 9).unwrap();
        assert_eq!(made.risky_ref().b, 9);
        made.zeroize();
        assert_eq!(*made.risky_ref(), Padded::zeroed());

        let region = key.into_wiped_region();
        // SAFETY: the region is still mapped, and the wipe initialised every
        // byte of the value's storage, padding included.
        let bytes =
            unsafe { core::slice::from_raw_parts(region.value_ptr(SIZE, ALIGN).as_ptr(), SIZE) };
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn move_in_wipes_the_source_slot() {
        let mut slot = ManuallyDrop::new([0xA5u8; 16]);
        let unfilled = Unfilled::<[u8; 16]>::allocate().unwrap();
        // SAFETY: `slot` is read below only as bytes, never as the array.
        let key = unsafe { unfilled.move_in(&mut slot) };
        assert_eq!(key.risky_ref(), &[0xA5u8; 16]);
        // SAFETY: the wipe initialises every byte of the slot to zero.
        let left_behind: [u8; 16] = unsafe { ptr::read((&*slot as *const [u8; 16]).cast()) };
        assert_eq!(left_behind, [0u8; 16]);
    }

    #[test]
    fn new_moves_without_running_drop_on_the_source() {
        // `new` takes the value by move; the slot it wipes is its own
        // parameter, observed directly in `move_in_wipes_the_source_slot`.
        // This pins the other half of the contract: no `Drop` runs on the
        // source, only on the value in the region, exactly once.
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
    fn relock_in_the_same_process_reports_the_known_state() {
        let mut key = Locked::new([1u8; 8]).unwrap();
        let before = key.locked();
        assert_eq!(key.relock().is_ok(), before);
        assert_eq!(key.locked(), before);
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
        // Three for the Unix region (base, length, owning pid; the
        // fallback's `Layout` costs the same), one for the boxed lock error.
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
        let constrained = matches!(unix::memlock_limit(), Some(limit) if limit < 1 << 20);
        if !constrained {
            assert!(key.locked(), "{:?}", key.lock_error());
        }
    }

    /// The `Locked:` count (KiB) and `VmFlags:` of the `/proc/self/smaps`
    /// entry that contains `addr`.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn smaps_entry(addr: usize) -> (Option<u64>, Option<String>) {
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
        (locked_kb, flags)
    }

    /// Whether `mlock` reports success without locking anything, as the
    /// sanitizer runtimes make it do (their shadow memory must never be
    /// pinned). Judged from a page of our own: if a successful `mlock` on
    /// it leaves the kernel counting nothing locked, `locked()` says
    /// nothing about what the kernel did in this process.
    #[cfg(all(target_os = "linux", not(miri)))]
    fn mlock_is_a_no_op() -> bool {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        // SAFETY: an anonymous private mapping of one page; checked below.
        let probe = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(probe, libc::MAP_FAILED);
        // SAFETY: `probe` is a page we own.
        let locked = unsafe { libc::mlock(probe, page) } == 0;
        let counted = smaps_entry(probe as usize).0.unwrap_or(0) > 0;
        // SAFETY: still our page, unlocked and unmapped exactly once.
        unsafe {
            let _ = libc::munlock(probe, page);
            let _ = libc::munmap(probe, page);
        }
        locked && !counted
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    #[test]
    fn the_kernel_reports_the_region_locked_and_not_dumpable() {
        let key = Locked::new([1u8; 32]).unwrap();
        // The dump exclusion does not depend on the lock, and nothing on an
        // unfiltered host refuses it, so it is never the reported
        // degradation here. A refused lock (a small RLIMIT_MEMLOCK) is
        // possible and is covered by the process tests; it only skips the
        // `Locked:` check below, not the `dd` flag. So does an `mlock` that
        // is a no-op in this process.
        assert!(
            !matches!(key.lock_error(), Some(LockError::Dump { .. })),
            "{:?}",
            key.lock_error()
        );
        let expect_locked = key.locked() && !mlock_is_a_no_op();
        let (locked_kb, flags) = smaps_entry(key.region.ptr().as_ptr() as usize);
        if expect_locked {
            assert!(locked_kb.unwrap_or(0) > 0, "Locked: {locked_kb:?}");
        }
        assert!(
            flags.as_deref().unwrap_or("").split(' ').any(|f| f == "dd"),
            "VmFlags: {flags:?}"
        );
    }
}
