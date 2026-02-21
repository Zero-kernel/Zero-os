//! Page Cache Implementation for Zero-OS
//!
//! Provides a global page cache for file-backed pages with:
//! - Per-inode indexing via BTreeMap
//! - Global hash-based lookup for fast access
//! - LRU list for page reclamation
//! - Dirty page tracking for writeback
//!
//! # Architecture
//!
//! ```text
//! GlobalPageCache
//!   ├── buckets: [RwLock<HashMap<(InodeId, PageIndex), Arc<PageCacheEntry>>>]
//!   └── lru: Mutex<LruList>
//!
//! AddressSpace (per inode)
//!   └── pages: RwLock<BTreeMap<PageIndex, Arc<PageCacheEntry>>>
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::buddy_allocator;

/// Page size constant (4KB)
pub const PAGE_SIZE: usize = 4096;

/// Number of hash buckets for global page cache lookup
const HASH_BUCKET_COUNT: usize = 256;

/// Inode identifier type
pub type InodeId = u64;

/// Page index within an inode (file offset / PAGE_SIZE)
pub type PageIndex = u64;

// ============================================================================
// Page Cache Entry
// ============================================================================

/// Flags for page state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    /// Page is invalid/not yet loaded
    Invalid = 0,
    /// Page data is valid and up-to-date
    Uptodate = 1,
    /// Page is currently being read from disk
    Reading = 2,
    /// Page is currently being written to disk
    Writeback = 3,
    /// Page has an I/O error
    Error = 4,
}

/// A cached page entry
///
/// Contains a physical page frame along with metadata for cache management.
pub struct PageCacheEntry {
    /// Physical frame number (PFN) of the page
    pub pfn: u64,

    /// Inode this page belongs to
    pub inode_id: InodeId,

    /// Page index within the inode
    pub index: PageIndex,

    /// Whether the page has been modified since last writeback
    dirty: AtomicBool,

    /// Reference count (number of active users)
    refcount: AtomicU32,

    /// Page state
    state: AtomicU32,

    /// Lock for I/O serialization (only one I/O operation at a time)
    io_lock: Mutex<()>,

    /// LRU list node index (for O(1) removal)
    lru_index: AtomicU64,
}

impl PageCacheEntry {
    /// Create a new page cache entry
    ///
    /// R42-4 FIX: Refcount now starts at 0 (no active pins).
    /// The Arc wrapper provides the actual reference counting for the cache.
    /// Callers who need to pin a page should use get()/put() explicitly.
    pub fn new(pfn: u64, inode_id: InodeId, index: PageIndex) -> Self {
        Self {
            pfn,
            inode_id,
            index,
            dirty: AtomicBool::new(false),
            refcount: AtomicU32::new(0), // R42-4 FIX: Start with 0 (no active pins)
            state: AtomicU32::new(PageState::Invalid as u32),
            io_lock: Mutex::new(()),
            lru_index: AtomicU64::new(u64::MAX),
        }
    }

    /// Get the physical frame number
    #[inline]
    pub fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Get the physical address of this page
    #[inline]
    pub fn physical_address(&self) -> u64 {
        self.pfn * PAGE_SIZE as u64
    }

    /// Check if the page is dirty
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    /// Mark the page as dirty
    #[inline]
    pub fn set_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Clear the dirty flag
    #[inline]
    pub fn clear_dirty(&self) {
        self.dirty.store(false, Ordering::Release);
    }

    /// Get the current reference count
    #[inline]
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Acquire)
    }

    /// Increment reference count
    #[inline]
    pub fn get(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::AcqRel) // lint-fetch-add: allow (page refcount)
    }

    /// Decrement reference count, returns true if this was the last reference
    #[inline]
    pub fn put(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Get the page state
    #[inline]
    pub fn state(&self) -> PageState {
        match self.state.load(Ordering::Acquire) {
            0 => PageState::Invalid,
            1 => PageState::Uptodate,
            2 => PageState::Reading,
            3 => PageState::Writeback,
            _ => PageState::Error,
        }
    }

    /// Set the page state
    #[inline]
    pub fn set_state(&self, state: PageState) {
        self.state.store(state as u32, Ordering::Release);
    }

    /// Check if page data is valid
    #[inline]
    pub fn is_uptodate(&self) -> bool {
        self.state() == PageState::Uptodate
    }

    /// Lock the page for I/O operations
    #[inline]
    pub fn lock_io(&self) -> spin::MutexGuard<'_, ()> {
        self.io_lock.lock()
    }

    /// Check if the page can be reclaimed
    ///
    /// R42-4 FIX: Use Arc::strong_count instead of internal refcount to determine
    /// reclaimability. A page can be reclaimed when:
    /// 1. Only the cache (bucket) and caller hold references (strong_count == 2)
    ///    - After pop_tail from LRU, the page has: one ref in bucket, one ref in local var
    /// 2. The page is not dirty (no pending writeback needed)
    /// 3. The page is not locked for I/O
    ///
    /// This fixes the issue where the internal refcount was only incremented
    /// but never decremented, preventing any page from ever being reclaimed.
    ///
    /// Note: Called from shrink() after the page has been removed from LRU.
    /// At that point, only the bucket and the local variable hold Arc references.
    pub fn can_reclaim(page: &alloc::sync::Arc<PageCacheEntry>) -> bool {
        // After LRU pop: bucket(1) + local var(1) = 2
        // Any external user would add more refs
        alloc::sync::Arc::strong_count(page) == 2
            && !page.is_dirty()
            && page.io_lock.try_lock().is_some()
    }
}

// R36-FIX: Implement Drop to free physical frame when page cache entry is dropped.
// This prevents memory leaks when pages are evicted from the cache during shrink().
impl Drop for PageCacheEntry {
    fn drop(&mut self) {
        // Free the physical frame back to the buddy allocator
        let phys_addr = self.pfn * PAGE_SIZE as u64;
        let frame = PhysFrame::containing_address(PhysAddr::new(phys_addr));
        buddy_allocator::free_physical_pages(frame, 1);
    }
}

// ============================================================================
// LRU List for Page Reclamation
// ============================================================================

/// LRU list entry
struct LruEntry {
    /// Reference to the page cache entry
    entry: Option<Arc<PageCacheEntry>>,
    /// Previous entry index
    prev: u64,
    /// Next entry index
    next: u64,
}

/// LRU list for tracking page access order
struct LruList {
    /// Array of LRU entries
    entries: Vec<LruEntry>,
    /// Head of the list (most recently used)
    head: u64,
    /// Tail of the list (least recently used)
    tail: u64,
    /// Number of active entries
    count: usize,
    /// Free list head
    free_head: u64,
}

impl LruList {
    /// Create a new LRU list with given capacity
    fn new(capacity: usize) -> Self {
        let mut entries = Vec::with_capacity(capacity);

        // Initialize free list
        for i in 0..capacity {
            entries.push(LruEntry {
                entry: None,
                prev: if i > 0 { i as u64 - 1 } else { u64::MAX },
                next: if i < capacity - 1 {
                    i as u64 + 1
                } else {
                    u64::MAX
                },
            });
        }

        Self {
            entries,
            head: u64::MAX,
            tail: u64::MAX,
            count: 0,
            free_head: if capacity > 0 { 0 } else { u64::MAX },
        }
    }

    /// Add a page to the front of the LRU list (most recently used)
    fn push_front(&mut self, page: Arc<PageCacheEntry>) -> Option<u64> {
        // Allocate from free list
        if self.free_head == u64::MAX {
            return None; // No space
        }

        let idx = self.free_head;
        self.free_head = self.entries[idx as usize].next;

        // Initialize entry
        let entry = &mut self.entries[idx as usize];
        entry.entry = Some(page.clone());
        entry.prev = u64::MAX;
        entry.next = self.head;

        // Update old head
        if self.head != u64::MAX {
            self.entries[self.head as usize].prev = idx;
        }

        // Update head
        self.head = idx;

        // Update tail if this is the first entry
        if self.tail == u64::MAX {
            self.tail = idx;
        }

        self.count += 1;

        // Store index in page entry
        page.lru_index.store(idx, Ordering::Release);

        Some(idx)
    }

    /// Move an existing entry to the front (mark as recently used)
    fn touch(&mut self, idx: u64) {
        if idx == u64::MAX || idx == self.head {
            return;
        }

        let idx_usize = idx as usize;

        // Remove from current position
        let prev = self.entries[idx_usize].prev;
        let next = self.entries[idx_usize].next;

        if prev != u64::MAX {
            self.entries[prev as usize].next = next;
        }
        if next != u64::MAX {
            self.entries[next as usize].prev = prev;
        }
        if self.tail == idx {
            self.tail = prev;
        }

        // Insert at front
        self.entries[idx_usize].prev = u64::MAX;
        self.entries[idx_usize].next = self.head;

        if self.head != u64::MAX {
            self.entries[self.head as usize].prev = idx;
        }
        self.head = idx;
    }

    /// Remove an entry from the LRU list
    fn remove(&mut self, idx: u64) -> Option<Arc<PageCacheEntry>> {
        if idx == u64::MAX {
            return None;
        }

        let idx_usize = idx as usize;
        let entry = self.entries[idx_usize].entry.take()?;

        // Update links
        let prev = self.entries[idx_usize].prev;
        let next = self.entries[idx_usize].next;

        if prev != u64::MAX {
            self.entries[prev as usize].next = next;
        } else {
            self.head = next;
        }

        if next != u64::MAX {
            self.entries[next as usize].prev = prev;
        } else {
            self.tail = prev;
        }

        // Add to free list
        self.entries[idx_usize].prev = u64::MAX;
        self.entries[idx_usize].next = self.free_head;
        self.free_head = idx;

        self.count -= 1;

        // Clear index in page entry
        entry.lru_index.store(u64::MAX, Ordering::Release);

        Some(entry)
    }

    /// Pop the tail (least recently used) entry
    fn pop_tail(&mut self) -> Option<Arc<PageCacheEntry>> {
        if self.tail == u64::MAX {
            return None;
        }
        self.remove(self.tail)
    }

    /// Get the number of entries
    fn len(&self) -> usize {
        self.count
    }
}

// ============================================================================
// Address Space (Per-Inode Page Index)
// ============================================================================

/// Per-inode address space for page indexing
pub struct AddressSpace {
    /// Inode identifier
    inode_id: InodeId,
    /// Pages indexed by page index
    pages: RwLock<BTreeMap<PageIndex, Arc<PageCacheEntry>>>,
    /// Number of pages in this address space
    nr_pages: AtomicU64,
    /// Number of dirty pages
    nr_dirty: AtomicU64,
}

impl AddressSpace {
    /// Create a new address space for an inode
    pub fn new(inode_id: InodeId) -> Self {
        Self {
            inode_id,
            pages: RwLock::new(BTreeMap::new()),
            nr_pages: AtomicU64::new(0),
            nr_dirty: AtomicU64::new(0),
        }
    }

    /// Get the inode ID
    #[inline]
    pub fn inode_id(&self) -> InodeId {
        self.inode_id
    }

    /// Find a page by index
    pub fn find_page(&self, index: PageIndex) -> Option<Arc<PageCacheEntry>> {
        let pages = self.pages.read();
        pages.get(&index).cloned()
    }

    /// Add a page to the address space
    pub fn add_page(&self, index: PageIndex, page: Arc<PageCacheEntry>) -> bool {
        let mut pages = self.pages.write();
        if pages.contains_key(&index) {
            return false;
        }
        pages.insert(index, page);
        self.nr_pages.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
        true
    }

    /// Remove a page from the address space
    pub fn remove_page(&self, index: PageIndex) -> Option<Arc<PageCacheEntry>> {
        let mut pages = self.pages.write();
        if let Some(page) = pages.remove(&index) {
            self.nr_pages.fetch_sub(1, Ordering::Relaxed);
            if page.is_dirty() {
                self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
            }
            Some(page)
        } else {
            None
        }
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&self, page: &PageCacheEntry) {
        if !page.is_dirty() {
            page.set_dirty();
            self.nr_dirty.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
        }
    }

    /// Clear dirty flag on a page
    pub fn clear_dirty(&self, page: &PageCacheEntry) {
        if page.is_dirty() {
            page.clear_dirty();
            self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get the number of pages
    pub fn nr_pages(&self) -> u64 {
        self.nr_pages.load(Ordering::Relaxed)
    }

    /// Get the number of dirty pages
    pub fn nr_dirty(&self) -> u64 {
        self.nr_dirty.load(Ordering::Relaxed)
    }

    /// Iterate over all pages (for truncation/invalidation)
    pub fn for_each_page<F>(&self, mut f: F)
    where
        F: FnMut(PageIndex, &Arc<PageCacheEntry>),
    {
        let pages = self.pages.read();
        for (index, page) in pages.iter() {
            f(*index, page);
        }
    }

    /// Truncate pages beyond the given index
    pub fn truncate(&self, from_index: PageIndex) -> Vec<Arc<PageCacheEntry>> {
        let mut pages = self.pages.write();
        let to_remove: Vec<_> = pages.range(from_index..).map(|(k, _)| *k).collect();

        let mut removed = Vec::new();
        for index in to_remove {
            if let Some(page) = pages.remove(&index) {
                self.nr_pages.fetch_sub(1, Ordering::Relaxed);
                if page.is_dirty() {
                    self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
                }
                removed.push(page);
            }
        }
        removed
    }

    /// Invalidate all pages (for unmount)
    pub fn invalidate(&self) -> Vec<Arc<PageCacheEntry>> {
        let mut pages = self.pages.write();
        // Collect all pages and clear the map
        let removed: Vec<_> = core::mem::take(&mut *pages)
            .into_iter()
            .map(|(_, page)| page)
            .collect();
        self.nr_pages.store(0, Ordering::Relaxed);
        self.nr_dirty.store(0, Ordering::Relaxed);
        removed
    }
}

// ============================================================================
// Global Page Cache
// ============================================================================

/// Hash function for (inode_id, page_index) -> bucket index
#[inline]
fn hash_key(inode_id: InodeId, index: PageIndex) -> usize {
    let h = inode_id.wrapping_mul(0x9e3779b97f4a7c15) ^ index.wrapping_mul(0x517cc1b727220a95);
    (h as usize) % HASH_BUCKET_COUNT
}

/// Global page cache
pub struct GlobalPageCache {
    /// Hash buckets for fast lookup
    buckets: Vec<RwLock<BTreeMap<(InodeId, PageIndex), Arc<PageCacheEntry>>>>,
    /// LRU list for reclamation
    lru: Mutex<LruList>,
    /// Total number of cached pages
    nr_pages: AtomicU64,
    /// Total number of dirty pages
    nr_dirty: AtomicU64,
    /// Maximum number of pages to cache
    max_pages: u64,
}

impl GlobalPageCache {
    /// Create a new global page cache
    pub fn new(max_pages: u64) -> Self {
        let mut buckets = Vec::with_capacity(HASH_BUCKET_COUNT);
        for _ in 0..HASH_BUCKET_COUNT {
            buckets.push(RwLock::new(BTreeMap::new()));
        }

        Self {
            buckets,
            lru: Mutex::new(LruList::new(max_pages as usize)),
            nr_pages: AtomicU64::new(0),
            nr_dirty: AtomicU64::new(0),
            max_pages,
        }
    }

    /// Find a page in the cache
    ///
    /// R42-4 FIX: Removed redundant page.get() call. The Arc clone already
    /// increments the reference count. The internal refcount field is now
    /// only used for explicit pinning by callers who need it.
    pub fn find_get_page(
        &self,
        inode_id: InodeId,
        index: PageIndex,
    ) -> Option<Arc<PageCacheEntry>> {
        let bucket_idx = hash_key(inode_id, index);
        let bucket = self.buckets[bucket_idx].read();

        if let Some(page) = bucket.get(&(inode_id, index)) {
            // Touch LRU (mark as recently used)
            let lru_idx = page.lru_index.load(Ordering::Acquire);
            if lru_idx != u64::MAX {
                let mut lru = self.lru.lock();
                lru.touch(lru_idx);
            }

            Some(page.clone())
        } else {
            None
        }
    }

    /// Add a page to the cache
    ///
    /// Returns the existing page if one already exists, or the new page if insertion succeeded.
    ///
    /// R42-4 FIX: Removed redundant existing.get() call on race condition path.
    pub fn add_to_cache(
        &self,
        inode_id: InodeId,
        index: PageIndex,
        page: Arc<PageCacheEntry>,
    ) -> Result<Arc<PageCacheEntry>, Arc<PageCacheEntry>> {
        let bucket_idx = hash_key(inode_id, index);
        let mut bucket = self.buckets[bucket_idx].write();

        // Check if page already exists
        if let Some(existing) = bucket.get(&(inode_id, index)) {
            // R42-4 FIX: Just clone the Arc, don't increment internal refcount
            return Err(existing.clone());
        }

        // Insert new page
        bucket.insert((inode_id, index), page.clone());
        self.nr_pages.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)

        // R28-3 Fix: Add to LRU with rollback on failure
        // If LRU is full and push_front fails, we must roll back the bucket insertion
        // to avoid creating unreclaimable orphan pages.
        let mut lru = self.lru.lock();
        if lru.push_front(page.clone()).is_none() {
            // LRU full: roll back the insertion
            drop(lru); // Release LRU lock before acquiring bucket lock again
            bucket.remove(&(inode_id, index));
            self.nr_pages.fetch_sub(1, Ordering::Relaxed);
            return Err(page);
        }

        Ok(page)
    }

    /// Remove a page from the cache
    pub fn remove_from_cache(
        &self,
        inode_id: InodeId,
        index: PageIndex,
    ) -> Option<Arc<PageCacheEntry>> {
        let bucket_idx = hash_key(inode_id, index);
        let mut bucket = self.buckets[bucket_idx].write();

        if let Some(page) = bucket.remove(&(inode_id, index)) {
            self.nr_pages.fetch_sub(1, Ordering::Relaxed);
            if page.is_dirty() {
                self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
            }

            // Remove from LRU
            let lru_idx = page.lru_index.load(Ordering::Acquire);
            if lru_idx != u64::MAX {
                let mut lru = self.lru.lock();
                lru.remove(lru_idx);
            }

            Some(page)
        } else {
            None
        }
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&self, page: &PageCacheEntry) {
        if !page.is_dirty() {
            page.set_dirty();
            self.nr_dirty.fetch_add(1, Ordering::Relaxed); // lint-fetch-add: allow (statistics counter)
        }
    }

    /// Clear dirty flag on a page
    pub fn clear_dirty(&self, page: &PageCacheEntry) {
        if page.is_dirty() {
            page.clear_dirty();
            self.nr_dirty.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Try to reclaim pages to free memory
    ///
    /// Returns the number of pages reclaimed.
    ///
    /// R42-5 FIX: Continue scanning LRU instead of stopping at first non-reclaimable page.
    /// An attacker could keep pages dirty/pinned to block reclamation if we stopped early.
    ///
    /// Lock ordering: bucket lock → LRU lock (same as find_get_page/add_to_cache)
    /// To avoid deadlock, we release LRU lock before acquiring bucket lock.
    pub fn shrink(&self, nr_to_reclaim: usize) -> usize {
        let mut reclaimed = 0;
        let mut scanned = 0usize;
        let max_scan = self.nr_pages.load(Ordering::Relaxed) as usize;

        while reclaimed < nr_to_reclaim && scanned < max_scan {
            // Phase 1: Pop candidate from LRU (with LRU lock)
            let page = {
                let mut lru = self.lru.lock();
                match lru.pop_tail() {
                    Some(p) => p,
                    None => break,
                }
            };
            // LRU lock released here
            scanned += 1;

            // R42-4 FIX: Use static method with Arc reference
            // R42-5 FIX: Check if page can be reclaimed, continue if not
            if !PageCacheEntry::can_reclaim(&page) {
                // Put it back at the front (it's actively used or dirty)
                let mut lru = self.lru.lock();
                lru.push_front(page);
                // R42-5 FIX: Continue scanning instead of breaking
                continue;
            }

            // Phase 2: Remove from hash bucket (with bucket lock only)
            // This follows lock order: bucket → LRU (we don't hold LRU here)
            let bucket_idx = hash_key(page.inode_id, page.index);
            {
                let mut bucket = self.buckets[bucket_idx].write();
                bucket.remove(&(page.inode_id, page.index));
            }

            self.nr_pages.fetch_sub(1, Ordering::Relaxed);
            reclaimed += 1;

            // R36-FIX: Physical frame is freed by Drop impl when Arc refcount reaches 0
        }

        reclaimed
    }

    /// Get cache statistics
    pub fn stats(&self) -> PageCacheStats {
        PageCacheStats {
            nr_pages: self.nr_pages.load(Ordering::Relaxed),
            nr_dirty: self.nr_dirty.load(Ordering::Relaxed),
            max_pages: self.max_pages,
            lru_len: self.lru.lock().len() as u64,
        }
    }

    /// Check if cache is under memory pressure
    pub fn under_pressure(&self) -> bool {
        self.nr_pages.load(Ordering::Relaxed) >= self.max_pages * 90 / 100
    }
}

/// Page cache statistics
#[derive(Debug, Clone, Copy)]
pub struct PageCacheStats {
    /// Total number of cached pages
    pub nr_pages: u64,
    /// Number of dirty pages
    pub nr_dirty: u64,
    /// Maximum cache size
    pub max_pages: u64,
    /// LRU list length
    pub lru_len: u64,
}

// ============================================================================
// Global Instance
// ============================================================================

use lazy_static::lazy_static;

lazy_static! {
    /// Global page cache instance (16K pages = 64MB default)
    pub static ref PAGE_CACHE: GlobalPageCache = GlobalPageCache::new(16384);
}

/// Initialize the page cache
pub fn init() {
    // Force lazy static initialization
    let stats = PAGE_CACHE.stats();
    klog_always!(
        "Page cache initialized: max_pages={}, current={}",
        stats.max_pages,
        stats.nr_pages
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Find or create a page in the cache
pub fn find_or_create_page(
    inode_id: InodeId,
    index: PageIndex,
    alloc_pfn: impl FnOnce() -> Option<u64>,
) -> Option<Arc<PageCacheEntry>> {
    // Try to find existing page
    if let Some(page) = PAGE_CACHE.find_get_page(inode_id, index) {
        return Some(page);
    }

    // Allocate new page
    let pfn = alloc_pfn()?;
    let page = Arc::new(PageCacheEntry::new(pfn, inode_id, index));

    // Try to add to cache
    match PAGE_CACHE.add_to_cache(inode_id, index, page) {
        Ok(p) => Some(p),
        Err(existing) => {
            // Race: another thread added the page first
            // Our page's Arc is dropped here, Drop impl frees the physical frame (R36-FIX)
            Some(existing)
        }
    }
}

/// Read a page from cache, or load from disk if not cached
pub fn read_page<F>(
    inode_id: InodeId,
    index: PageIndex,
    alloc_pfn: impl FnOnce() -> Option<u64>,
    read_from_disk: F,
) -> Option<Arc<PageCacheEntry>>
where
    F: FnOnce(&PageCacheEntry) -> Result<(), ()>,
{
    // Find or create the page
    let page = find_or_create_page(inode_id, index, alloc_pfn)?;

    // If page is already up-to-date, return it
    if page.is_uptodate() {
        return Some(page);
    }

    // Perform I/O with lock held in a block scope
    let success = {
        // Lock page for I/O
        let _io_lock = page.lock_io();

        // Double-check after acquiring lock
        if page.is_uptodate() {
            true
        } else {
            // Set state to reading
            page.set_state(PageState::Reading);

            // Read from disk
            if read_from_disk(&page).is_ok() {
                page.set_state(PageState::Uptodate);
                true
            } else {
                page.set_state(PageState::Error);
                false
            }
        }
    };

    if success {
        Some(page)
    } else {
        None
    }
}

/// Write a page to disk (for writeback)
pub fn writeback_page<F>(page: &PageCacheEntry, write_to_disk: F) -> Result<(), ()>
where
    F: FnOnce(&PageCacheEntry) -> Result<(), ()>,
{
    if !page.is_dirty() {
        return Ok(());
    }

    // Lock page for I/O
    let _io_lock = page.lock_io();

    // Double-check dirty flag
    if !page.is_dirty() {
        return Ok(());
    }

    // Set state to writeback
    page.set_state(PageState::Writeback);

    // Write to disk
    let result = write_to_disk(page);

    if result.is_ok() {
        PAGE_CACHE.clear_dirty(page);
        page.set_state(PageState::Uptodate);
    } else {
        page.set_state(PageState::Error);
    }

    result
}

// ============================================================================
// Writeback and Reclaim
// ============================================================================

/// Writeback statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct WritebackStats {
    /// Number of pages written back
    pub pages_written: u64,
    /// Number of pages that failed writeback
    pub pages_failed: u64,
    /// Number of pages skipped (already clean)
    pub pages_skipped: u64,
}

/// Scan the LRU list and writeback dirty pages
///
/// Returns writeback statistics.
pub fn writeback_dirty_pages<F>(max_pages: usize, write_fn: F) -> WritebackStats
where
    F: Fn(&PageCacheEntry) -> Result<(), ()>,
{
    let mut stats = WritebackStats::default();
    let mut pages_to_writeback = Vec::with_capacity(max_pages);

    // Phase 1: Collect dirty pages from LRU (with LRU lock)
    {
        let lru = PAGE_CACHE.lru.lock();

        // Walk the LRU from tail (oldest) to head
        let mut idx = lru.tail;
        while idx != u64::MAX && pages_to_writeback.len() < max_pages {
            if let Some(entry) = &lru.entries[idx as usize].entry {
                if entry.is_dirty() {
                    pages_to_writeback.push(entry.clone());
                }
            }
            // Move toward head
            idx = lru.entries[idx as usize].prev;
        }
    }
    // LRU lock released

    // Phase 2: Write back each dirty page (no global locks held)
    for page in pages_to_writeback {
        if !page.is_dirty() {
            stats.pages_skipped += 1;
            continue;
        }

        // Try to lock page for I/O
        if let Some(_io_lock) = page.io_lock.try_lock() {
            // Double-check dirty flag
            if !page.is_dirty() {
                stats.pages_skipped += 1;
                continue;
            }

            // Set state to writeback
            page.set_state(PageState::Writeback);

            // Write to disk
            if write_fn(&page).is_ok() {
                PAGE_CACHE.clear_dirty(&page);
                page.set_state(PageState::Uptodate);
                stats.pages_written += 1;
            } else {
                page.set_state(PageState::Error);
                stats.pages_failed += 1;
            }
        } else {
            // Page is locked by another I/O operation, skip it
            stats.pages_skipped += 1;
        }
    }

    stats
}

/// Reclaim memory by evicting clean pages
///
/// This function is called when memory pressure is high.
/// Returns the number of pages freed.
pub fn reclaim_pages(nr_to_reclaim: usize) -> usize {
    PAGE_CACHE.shrink(nr_to_reclaim)
}

/// Sync all dirty pages for an inode
///
/// This is called on fsync() to ensure all data is persisted.
pub fn sync_inode<F>(address_space: &AddressSpace, write_fn: F) -> Result<(), ()>
where
    F: Fn(&PageCacheEntry) -> Result<(), ()>,
{
    let mut pages_to_sync = Vec::new();

    // Collect all dirty pages from the address space
    address_space.for_each_page(|_, page| {
        if page.is_dirty() {
            pages_to_sync.push(page.clone());
        }
    });

    // Write back each dirty page
    let mut had_error = false;
    for page in pages_to_sync {
        if writeback_page(&page, &write_fn).is_err() {
            had_error = true;
        }
    }

    if had_error {
        Err(())
    } else {
        Ok(())
    }
}

/// Memory pressure callback interface
///
/// Called by the memory allocator when memory is low.
pub trait MemoryPressureHandler: Send + Sync {
    /// Called when memory pressure is detected
    fn on_memory_pressure(&self, nr_pages_needed: usize) -> usize;
}

/// Page cache memory pressure handler
pub struct PageCachePressureHandler;

impl MemoryPressureHandler for PageCachePressureHandler {
    fn on_memory_pressure(&self, nr_pages_needed: usize) -> usize {
        // First, try to reclaim clean pages
        let mut freed = reclaim_pages(nr_pages_needed);

        if freed < nr_pages_needed {
            // Not enough clean pages, need to writeback dirty pages first
            // In a real implementation, this would trigger async writeback
            // For now, we just report how many we could free
            klog_always!(
                "Page cache: memory pressure, freed {} pages (needed {})",
                freed,
                nr_pages_needed
            );
        }

        freed
    }
}

/// Global memory pressure handler instance
pub static PRESSURE_HANDLER: PageCachePressureHandler = PageCachePressureHandler;
