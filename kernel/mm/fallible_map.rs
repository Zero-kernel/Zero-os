//! `FallibleOrderedMap` — a small, allocation-fallible ordered map for no_std
//! kernel metadata (next-phase #11 / R165-14, R162-7).
//!
//! # Why this exists
//!
//! Stable `no_std` `alloc::collections::BTreeMap` has **no** allocation-fallible
//! insertion or construction API: its `try_insert` only reports *key collisions*,
//! never allocation failure, and it has no `try_reserve`. Every `BTreeMap::insert`
//! / `FromIterator` therefore routes through the global allocator and, on OOM,
//! invokes `handle_alloc_error` — an **abort/panic**, not a recoverable error.
//!
//! `MmState.mmap_regions` is user-influenced (a process can create up to
//! `MAX_MAP_COUNT` ≈ 65536 regions via `mmap`), and `fork_inner` rebuilds the
//! child's map by collecting that snapshot into a fresh `BTreeMap`. Under memory
//! pressure that collect — and every per-region `insert` in mmap/munmap/mprotect
//! — was an infallible allocation that could abort the kernel (AD-02 tech debt).
//!
//! # Design
//!
//! This map stores its entries in a single `Vec<(K, V)>` kept **sorted by key**.
//! `Vec::try_reserve` / `try_reserve_exact` are the *only* stable, fallible
//! allocation primitives in `no_std`, so backing the map with a `Vec` makes every
//! growth path recoverable:
//!
//! * `try_insert` binary-searches; an in-place replacement of an existing key
//!   never allocates, and a new key calls `Vec::try_reserve(1)` **before** the
//!   `Vec::insert`, which (with capacity guaranteed) cannot then reallocate.
//! * `try_reserve(n)` lets a caller pre-reserve capacity so a *sequence* of
//!   inserts (e.g. an mprotect region split) is transactional — none can fail
//!   mid-way and leave a partially-mutated map.
//! * `from_sorted_vec` adopts an already-sorted, already-fallibly-allocated `Vec`
//!   in O(1) with **zero** allocation — used by `fork` to clone the parent's map.
//! * `try_clone` reserves exact capacity up front, then clones entries.
//!
//! The deliberate trade-off (Safety > Efficiency > Speed): point lookup / range
//! bounds are O(log n) via binary search, but `try_insert` / `remove` are O(n)
//! because of the `Vec` shift. The map is bounded by `MAX_MAP_COUNT` and the
//! common case is a handful of regions, so the cost is acceptable — and a
//! recoverable O(n) insert is strictly preferable to an O(log n) insert that
//! aborts the kernel under OOM.
//!
//! The read API is intentionally method-name-compatible with the `BTreeMap`
//! subset the kernel uses (`get`, `get_mut`, `remove`, `iter`, `values`, `keys`,
//! `range`, `range_mut`, `len`, `clear`), so migrating a field only changes the
//! *fallible* sites (`insert` → `try_insert`, construction → `from_sorted_vec`).

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use core::ops::{Bound, RangeBounds};

/// An ordered map backed by a key-sorted `Vec`, with allocation-fallible growth.
///
/// `K: Ord` keys are unique; iteration and ranges yield entries in ascending key
/// order. The type deliberately does **not** implement `Clone` — an infallible
/// clone would reintroduce the OOM-abort class this map exists to remove. Use
/// [`FallibleOrderedMap::try_clone`] instead.
#[derive(Debug)]
pub struct FallibleOrderedMap<K: Ord, V> {
    /// Entries sorted strictly-ascending by key. Invariant maintained by every
    /// mutator: `entries[i].0 < entries[i + 1].0` for all valid `i`.
    entries: Vec<(K, V)>,
}

impl<K: Ord, V> FallibleOrderedMap<K, V> {
    /// Create an empty map. Const so it can initialize statics if ever needed.
    #[inline]
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Locate `key`: `Ok(idx)` if present at `idx`, else `Err(idx)` where `idx`
    /// is the sorted insertion position.
    #[inline]
    fn find(&self, key: &K) -> Result<usize, usize> {
        self.entries.binary_search_by(|(probe, _)| probe.cmp(key))
    }

    /// Shared reference to the value for `key`, if present. O(log n).
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        match self.find(key) {
            Ok(idx) => Some(&self.entries[idx].1),
            Err(_) => None,
        }
    }

    /// Mutable reference to the value for `key`, if present. O(log n).
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self.find(key) {
            Ok(idx) => Some(&mut self.entries[idx].1),
            Err(_) => None,
        }
    }

    /// Whether `key` is present. O(log n).
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        self.find(key).is_ok()
    }

    /// Reserve capacity for at least `additional` more entries, fallibly.
    ///
    /// Pre-reserving makes a *sequence* of subsequent `try_insert` calls
    /// transactional: once capacity exists, the `Vec::insert` inside each
    /// `try_insert` cannot reallocate, so none of the inserts can fail and the
    /// caller never observes a partially-mutated map (e.g. mprotect's region
    /// split, which adds up to two new keys).
    #[inline]
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.entries.try_reserve(additional)
    }

    /// Insert `value` for `key`, fallibly.
    ///
    /// Returns `Ok(Some(old))` if `key` was already present (replaced in place —
    /// **no allocation**), `Ok(None)` if it was newly inserted, or
    /// `Err(TryReserveError)` if reserving room for the new entry failed (the map
    /// is then left **unchanged**). Mirrors `BTreeMap::insert`'s return value.
    pub fn try_insert(&mut self, key: K, value: V) -> Result<Option<V>, TryReserveError> {
        match self.find(&key) {
            Ok(idx) => Ok(Some(core::mem::replace(&mut self.entries[idx].1, value))),
            Err(idx) => {
                // Reserve BEFORE mutating: on failure the map is untouched.
                self.entries.try_reserve(1)?;
                // Capacity is now guaranteed, so `insert` will not reallocate.
                self.entries.insert(idx, (key, value));
                Ok(None)
            }
        }
    }

    /// Remove and return the value for `key`, if present. O(n) (Vec shift).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        match self.find(key) {
            Ok(idx) => Some(self.entries.remove(idx).1),
            Err(_) => None,
        }
    }

    /// Remove all entries (retains capacity).
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate `(&K, &V)` in ascending key order.
    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Iterate `(&K, &mut V)` in ascending key order (keys are immutable).
    #[inline]
    pub fn iter_mut(&mut self) -> impl DoubleEndedIterator<Item = (&K, &mut V)> {
        self.entries.iter_mut().map(|(k, v)| (&*k, v))
    }

    /// Iterate values in ascending key order.
    #[inline]
    pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// Iterate values mutably in ascending key order.
    #[inline]
    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, v)| v)
    }

    /// Iterate keys in ascending order.
    #[inline]
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> {
        self.entries.iter().map(|(k, _)| k)
    }

    /// First index whose key is `>= key` (lower bound).
    #[inline]
    fn lower_bound(&self, key: &K) -> usize {
        self.entries.partition_point(|(probe, _)| probe < key)
    }

    /// First index whose key is `> key` (upper bound).
    #[inline]
    fn upper_bound(&self, key: &K) -> usize {
        self.entries.partition_point(|(probe, _)| probe <= key)
    }

    /// Resolve a key range to a `[lo, hi)` slice index range, honoring all
    /// `RangeBounds` forms. Always returns `lo <= hi` (an out-of-order or empty
    /// range collapses to an empty slice), so the returned slice is valid.
    fn bounds_to_indices<R: RangeBounds<K>>(&self, range: &R) -> (usize, usize) {
        let lo = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(k) => self.lower_bound(k),
            Bound::Excluded(k) => self.upper_bound(k),
        };
        let hi = match range.end_bound() {
            Bound::Unbounded => self.entries.len(),
            Bound::Included(k) => self.upper_bound(k),
            Bound::Excluded(k) => self.lower_bound(k),
        };
        // Clamp: a caller-supplied inverted range (e.g. `30..10`) must yield an
        // empty iterator, never a panicking out-of-order slice index.
        if hi < lo {
            (lo, lo)
        } else {
            (lo, hi)
        }
    }

    /// Iterate `(&K, &V)` whose keys fall within `range`, in ascending order.
    /// Returns a `DoubleEndedIterator` so callers may use `.next_back()`.
    #[inline]
    pub fn range<R: RangeBounds<K>>(&self, range: R) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        let (lo, hi) = self.bounds_to_indices(&range);
        self.entries[lo..hi].iter().map(|(k, v)| (k, v))
    }

    /// Iterate `(&K, &mut V)` whose keys fall within `range`, in ascending order.
    #[inline]
    pub fn range_mut<R: RangeBounds<K>>(
        &mut self,
        range: R,
    ) -> impl DoubleEndedIterator<Item = (&K, &mut V)> {
        let (lo, hi) = self.bounds_to_indices(&range);
        self.entries[lo..hi].iter_mut().map(|(k, v)| (&*k, v))
    }

    /// Fallibly clone the map. Reserves exact capacity for the backing `Vec` up
    /// front so the clone either fully succeeds or leaves nothing behind (no
    /// partial allocation aborts).
    ///
    /// CAVEAT: only the *backing `Vec`* allocation is fallible. If `K::clone` or
    /// `V::clone` themselves allocate (e.g. `String`, `Vec`), those inner
    /// allocations remain infallible and could still abort under OOM. This is
    /// fully OOM-safe only for non-allocating `K`/`V` — which is the case for the
    /// kernel's use (`K = usize`, `V = MmapEntry`, both `Copy`).
    pub fn try_clone(&self) -> Result<Self, TryReserveError>
    where
        K: Clone,
        V: Clone,
    {
        let mut entries: Vec<(K, V)> = Vec::new();
        entries.try_reserve_exact(self.entries.len())?;
        for (k, v) in self.entries.iter() {
            // Capacity is guaranteed by the reserve above, so push cannot
            // reallocate (and thus cannot abort).
            entries.push((k.clone(), v.clone()));
        }
        Ok(Self { entries })
    }

    /// Adopt an already key-sorted `Vec` as the map's backing store in O(1) with
    /// **no allocation**. The caller must guarantee strictly-ascending unique
    /// keys (debug-asserted). Used by `fork`, whose snapshot `Vec` is built —
    /// fallibly — from the parent's already-sorted map.
    pub fn from_sorted_vec(entries: Vec<(K, V)>) -> Self {
        debug_assert!(
            entries.windows(2).all(|w| w[0].0 < w[1].0),
            "FallibleOrderedMap::from_sorted_vec requires strictly-ascending unique keys"
        );
        Self { entries }
    }
}

impl<K: Ord, V> Default for FallibleOrderedMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// In-kernel self-test (mirrors the `mm::buddy_allocator::run_self_test` style).
/// Wired into the boot-time integration suite; any `assert!` failure panics the
/// kernel, which `make test` / `make boot-check` detect via the serial log.
pub fn run_fallible_ordered_map_self_test() {
    let mut map: FallibleOrderedMap<usize, usize> = FallibleOrderedMap::new();
    assert!(map.is_empty(), "fresh map must be empty");
    assert_eq!(map.len(), 0);

    // Out-of-order inserts must produce sorted storage.
    assert_eq!(map.try_insert(20, 2).expect("insert 20"), None);
    assert_eq!(map.try_insert(10, 1).expect("insert 10"), None);
    assert_eq!(map.try_insert(30, 3).expect("insert 30"), None);
    assert_eq!(map.len(), 3);

    // Lookups.
    assert_eq!(map.get(&10), Some(&1));
    assert_eq!(map.get(&25), None);
    assert!(map.contains_key(&30) && !map.contains_key(&31));

    // In-place replacement returns the old value and does not grow.
    assert_eq!(map.try_insert(20, 22).expect("replace 20"), Some(2));
    assert_eq!(map.get(&20), Some(&22));
    assert_eq!(map.len(), 3);

    // Ordered key iteration.
    let keys: Vec<usize> = map.keys().copied().collect();
    assert_eq!(keys, alloc::vec![10usize, 20, 30]);

    // Half-open range semantics + DoubleEnded `.next_back()`.
    assert_eq!(
        map.range(..20).next_back().map(|(&k, &v)| (k, v)),
        Some((10, 1))
    );
    assert_eq!(
        map.range(10..30).next_back().map(|(&k, &v)| (k, v)),
        Some((20, 22))
    );
    assert_eq!(map.range(10..30).count(), 2); // 10 and 20, not 30 (exclusive end)
    assert_eq!(map.range(..=30).count(), 3); // inclusive end covers 30
    // Inverted range must be empty, never panic.
    assert_eq!(map.range(30..10).count(), 0);

    // range_mut mutates only in-range values.
    for (_, v) in map.range_mut(10..30) {
        *v += 100;
    }
    assert_eq!(map.get(&10), Some(&101));
    assert_eq!(map.get(&20), Some(&122));
    assert_eq!(map.get(&30), Some(&3)); // 30 untouched (exclusive)

    // try_reserve makes a following insert allocation-free (smoke check it works).
    map.try_reserve(4).expect("reserve");
    assert_eq!(map.try_insert(40, 4).expect("insert 40"), None);

    // try_clone is independent of the source.
    let mut cloned = map.try_clone().expect("clone");
    assert_eq!(cloned.len(), map.len());
    assert_eq!(cloned.get(&20), Some(&122));
    cloned.try_insert(20, 999).expect("mutate clone");
    assert_eq!(map.get(&20), Some(&122), "clone must not alias source");

    // remove returns the value and shifts the rest.
    assert_eq!(map.remove(&20), Some(122));
    assert_eq!(map.get(&20), None);
    assert_eq!(map.remove(&20), None); // idempotent

    // from_sorted_vec adopts a pre-sorted Vec with no allocation.
    let mut raw: Vec<(usize, usize)> = Vec::new();
    raw.try_reserve_exact(3).expect("reserve raw");
    raw.push((1, 10));
    raw.push((2, 20));
    raw.push((3, 30));
    let adopted = FallibleOrderedMap::from_sorted_vec(raw);
    assert_eq!(adopted.len(), 3);
    assert_eq!(adopted.range(2..=3).count(), 2);
    assert_eq!(adopted.get(&1), Some(&10));
}
