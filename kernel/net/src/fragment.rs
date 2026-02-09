//! IPv4 Fragment Reassembly for Zero-OS
//!
//! This module provides secure IP fragment reassembly with anti-DoS protections.
//!
//! # Security Features
//! - RFC 5722 overlap detection (reject overlapping fragments)
//! - Per-source queue limits (prevent memory exhaustion)
//! - Global fragment count limits
//! - Reassembly timeout (45 seconds)
//! - First fragment L4 header visibility requirement
//! - Rate limiting per source
//!
//! # References
//! - RFC 791: Internet Protocol (fragmentation)
//! - RFC 815: IP Datagram Reassembly Algorithms
//! - RFC 5722: Handling of Overlapping IPv4 Fragments
//! - RFC 8900: IP Fragmentation Considered Fragile

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::ipv4::Ipv4Header;

// ============================================================================
// Constants - Security Limits
// ============================================================================

/// R101-12 FIX: Reduced fragment reassembly timeout from 45s to 30s.
///
/// The previous 45-second timeout allowed attackers to hold reassembly buffer
/// memory for longer. Linux default is 30 seconds (net.ipv4.ipfrag_time).
/// Reducing timeout limits the memory pressure window from crafted fragments
/// that are never completed.
pub const FRAG_TIMEOUT_MS: u64 = 30_000;

/// Maximum reassembled packet size (IPv4 max is 65535)
pub const MAX_PACKET_SIZE: usize = 65_535;

/// Maximum fragments per reassembly queue
pub const MAX_FRAGS_PER_QUEUE: usize = 64;

/// R62-2 FIX: Maximum buffered bytes per reassembly queue (DoS bound)
/// 512KB per queue prevents single attacker from exhausting memory
pub const MAX_BYTES_PER_QUEUE: usize = 512 * 1024;

/// Maximum queues per source IP address
pub const MAX_QUEUES_PER_SRC: usize = 256;

/// Global maximum reassembly queues
pub const GLOBAL_MAX_QUEUES: usize = 4096;

/// Global maximum fragments across all queues
pub const GLOBAL_MAX_FRAGS: usize = 32_768;

/// R62-2 FIX: Global maximum buffered fragment bytes (DoS bound)
/// 64MB global limit prevents memory exhaustion from fragment floods
pub const GLOBAL_MAX_FRAG_BYTES: usize = 64 * 1024 * 1024;

/// Minimum L4 header bytes required in first fragment
/// (8 bytes covers UDP header and TCP source/dest ports)
pub const MIN_L4_HEADER_BYTES: usize = 8;

/// Rate limit tokens per source (fragments per window)
pub const RATE_LIMIT_TOKENS: u32 = 128;

/// Rate limit refill window in milliseconds
pub const RATE_LIMIT_WINDOW_MS: u64 = 1000;

// ============================================================================
// Statistics
// ============================================================================

/// Fragment reassembly statistics
#[derive(Debug, Default)]
pub struct FragmentStats {
    /// Fragments received
    pub fragments_received: AtomicU64,
    /// Successfully reassembled packets
    pub reassembled: AtomicU64,
    /// Fragments dropped due to timeout
    pub timeout_drops: AtomicU64,
    /// Fragments dropped due to overlap
    pub overlap_drops: AtomicU64,
    /// Fragments dropped due to queue limit
    pub queue_limit_drops: AtomicU64,
    /// Fragments dropped due to global limit
    pub global_limit_drops: AtomicU64,
    /// Fragments dropped due to rate limit
    pub rate_limit_drops: AtomicU64,
    /// Fragments dropped - first too small
    pub first_too_small_drops: AtomicU64,
    /// Fragments dropped - too large
    pub too_large_drops: AtomicU64,
    /// Current active queues
    pub active_queues: AtomicU32,
    /// Current buffered fragments
    pub buffered_fragments: AtomicU32,
    /// R62-2 FIX: Current buffered bytes
    pub buffered_bytes: AtomicU64,
}

impl FragmentStats {
    pub const fn new() -> Self {
        Self {
            fragments_received: AtomicU64::new(0),
            reassembled: AtomicU64::new(0),
            timeout_drops: AtomicU64::new(0),
            overlap_drops: AtomicU64::new(0),
            queue_limit_drops: AtomicU64::new(0),
            global_limit_drops: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            first_too_small_drops: AtomicU64::new(0),
            too_large_drops: AtomicU64::new(0),
            active_queues: AtomicU32::new(0),
            buffered_fragments: AtomicU32::new(0),
            buffered_bytes: AtomicU64::new(0),
        }
    }

    /// R66-11 FIX: Atomically reserve a fragment slot if within limit.
    /// Returns true if reservation succeeded, false if limit would be exceeded.
    pub fn try_reserve_fragment(&self, max_frags: usize) -> bool {
        self.buffered_fragments
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if (current as usize) < max_frags {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// R66-11 FIX: Atomically reserve bytes if within limit.
    /// Returns true if reservation succeeded, false if limit would be exceeded.
    pub fn try_reserve_bytes(&self, bytes: usize, max_bytes: usize) -> bool {
        self.buffered_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let new_val = current.saturating_add(bytes as u64);
                if (new_val as usize) <= max_bytes {
                    Some(new_val)
                } else {
                    None
                }
            })
            .is_ok()
    }

    /// R66-11 FIX: Release previously reserved fragment slot.
    pub fn release_fragment(&self) {
        // Saturating sub to handle edge cases
        self.buffered_fragments
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            })
            .ok();
    }

    /// R66-11 FIX: Release previously reserved bytes.
    pub fn release_bytes(&self, bytes: usize) {
        self.buffered_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(bytes as u64))
            })
            .ok();
    }
}

// ============================================================================
// Drop Reasons
// ============================================================================

/// Reason a fragment was dropped
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentDropReason {
    /// Rate limited (too many fragments from source)
    RateLimited,
    /// Fragment would exceed max packet size
    TooLarge,
    /// Queue has too many fragments
    QueueFragLimit,
    /// R62-2 FIX: Queue has too many buffered bytes
    QueueByteLimit,
    /// First fragment too small to contain L4 header
    FirstTooSmall,
    /// Overlapping fragments (RFC 5722 violation)
    Overlap,
    /// Global queue limit exceeded
    GlobalQueueLimit,
    /// Global fragment limit exceeded
    GlobalFragLimit,
    /// R62-2 FIX: Global byte limit exceeded
    GlobalByteLimit,
    /// Per-source queue limit exceeded
    PerSourceLimit,
    /// Reassembly timeout
    Timeout,
    /// Zero-length fragment
    ZeroLength,
    /// Duplicate fragment
    Duplicate,
}

// ============================================================================
// Fragment Key
// ============================================================================

/// Key to identify a fragment reassembly queue
///
/// Per RFC 791, fragments are identified by (src, dst, protocol, identification).
/// Ord is derived to allow direct use as BTreeMap key (avoiding lossy u64 packing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub identification: u16,
}

impl FragmentKey {
    /// Create key from IPv4 header
    pub fn from_header(hdr: &Ipv4Header) -> Self {
        Self {
            src: hdr.src.octets(),
            dst: hdr.dst.octets(),
            protocol: hdr.protocol,
            identification: hdr.identification,
        }
    }

    /// Get source IP for per-source tracking
    pub fn src_ip(&self) -> u32 {
        u32::from_be_bytes(self.src)
    }
}

// ============================================================================
// Fragment Hole Tracking (RFC 815)
// ============================================================================

/// A hole in the reassembly buffer
///
/// Represents a gap [start, end) that still needs to be filled.
#[derive(Debug, Clone, Copy)]
struct FragmentHole {
    /// Start offset (inclusive)
    start: u16,
    /// End offset (exclusive)
    end: u16,
}

// ============================================================================
// Per-Source Rate Limiter
// ============================================================================

/// Token bucket rate limiter
struct RateLimiter {
    tokens: u32,
    last_refill_ms: u64,
}

impl RateLimiter {
    fn new(now_ms: u64) -> Self {
        Self {
            tokens: RATE_LIMIT_TOKENS,
            last_refill_ms: now_ms,
        }
    }

    fn allow(&mut self, cost: u32, now_ms: u64) -> bool {
        // Refill tokens based on elapsed time
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        let refill = ((elapsed as u64 * RATE_LIMIT_TOKENS as u64) / RATE_LIMIT_WINDOW_MS) as u32;
        self.tokens = self.tokens.saturating_add(refill).min(RATE_LIMIT_TOKENS);
        self.last_refill_ms = now_ms;

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Fragment Queue
// ============================================================================

/// A single reassembly queue for one IP datagram
struct FragmentQueue {
    /// Queue key
    key: FragmentKey,
    /// Creation timestamp (ms)
    created_ms: u64,
    /// Expiration timestamp (ms)
    expires_at_ms: u64,
    /// Total length once last fragment received
    total_len: Option<u16>,
    /// Number of fragments received
    received_frags: usize,
    /// Total bytes received
    received_bytes: usize,
    /// Hole list (gaps to fill)
    holes: Vec<FragmentHole>,
    /// Fragment data keyed by offset
    frags: BTreeMap<u16, Vec<u8>>,
    /// First fragment (offset 0) received
    have_first: bool,
    /// Last fragment (MF=0) received
    have_last: bool,
    /// First fragment has enough bytes for L4 header
    l4_header_ok: bool,
    /// Rate limiter for this source
    rate_limiter: RateLimiter,
}

impl FragmentQueue {
    fn new(key: FragmentKey, now_ms: u64) -> Self {
        Self {
            key,
            created_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(FRAG_TIMEOUT_MS),
            total_len: None,
            received_frags: 0,
            received_bytes: 0,
            // Initial hole: entire possible packet range
            holes: alloc::vec![FragmentHole {
                start: 0,
                end: u16::MAX
            }],
            frags: BTreeMap::new(),
            have_first: false,
            have_last: false,
            l4_header_ok: false,
            rate_limiter: RateLimiter::new(now_ms),
        }
    }

    /// Insert a fragment into the queue
    ///
    /// Returns Ok(true) if reassembly is now complete.
    fn insert(
        &mut self,
        offset: u16,
        more_fragments: bool,
        data: &[u8],
        now_ms: u64,
    ) -> Result<bool, FragmentDropReason> {
        let len = data.len() as u16;

        // Rate limiting
        if !self.rate_limiter.allow(1, now_ms) {
            return Err(FragmentDropReason::RateLimited);
        }

        // Zero-length fragments are invalid
        if len == 0 {
            return Err(FragmentDropReason::ZeroLength);
        }

        // Check fragment count limit
        if self.received_frags >= MAX_FRAGS_PER_QUEUE {
            return Err(FragmentDropReason::QueueFragLimit);
        }

        // R62-2 FIX: Check per-queue byte limit before accepting fragment
        // This prevents a single source from exhausting memory with large fragments
        if self.received_bytes.saturating_add(data.len()) > MAX_BYTES_PER_QUEUE {
            return Err(FragmentDropReason::QueueByteLimit);
        }

        let frag_start = offset;
        let frag_end = offset
            .checked_add(len)
            .ok_or(FragmentDropReason::TooLarge)?;

        // Check max packet size
        if frag_end as usize > MAX_PACKET_SIZE {
            return Err(FragmentDropReason::TooLarge);
        }

        // Handle first fragment (offset 0)
        // Note: have_first is set immediately since we need it for L4 header check
        let is_first = offset == 0;
        if is_first {
            self.have_first = true;
            // Require minimum L4 header visibility
            self.l4_header_ok = data.len() >= MIN_L4_HEADER_BYTES;
            if !self.l4_header_ok {
                return Err(FragmentDropReason::FirstTooSmall);
            }
        }

        // Check if this is last fragment (MF=0) and validate size
        // Note: We defer setting have_last/total_len until after validation succeeds
        let is_last = !more_fragments;
        if is_last {
            if frag_end as usize > MAX_PACKET_SIZE {
                return Err(FragmentDropReason::TooLarge);
            }
            // Security: If we already have fragments beyond this new total_len,
            // it's an inconsistent/malicious datagram - reject as overlap
            // This catches attacks that try to shrink the packet after data is buffered
            for (&stored_off, stored_data) in &self.frags {
                let stored_end = stored_off.saturating_add(stored_data.len() as u16);
                if stored_end > frag_end {
                    return Err(FragmentDropReason::Overlap);
                }
            }
        }

        // Determine max valid offset for hole clipping
        // Use tentative total_len if this is last fragment, otherwise existing or max
        let max_end = if is_last {
            frag_end
        } else {
            self.total_len.unwrap_or(u16::MAX)
        };

        // RFC 5722: Overlap detection against existing fragments
        // Check previous fragment
        if let Some((&prev_off, prev_data)) = self.frags.range(..=frag_start).next_back() {
            let prev_end = prev_off.saturating_add(prev_data.len() as u16);
            if prev_end > frag_start {
                return Err(FragmentDropReason::Overlap);
            }
        }

        // Check next fragment
        if let Some((&next_off, _)) = self.frags.range(frag_start..).next() {
            if next_off < frag_end {
                return Err(FragmentDropReason::Overlap);
            }
        }

        // RFC 815 hole algorithm: fragment must fill part of a hole
        // Holes are clipped to max_end to allow reassembly to complete
        let mut new_holes = Vec::with_capacity(self.holes.len() + 1);
        let mut covered = false;

        for hole in self.holes.drain(..) {
            // Skip holes entirely beyond the known packet length
            if hole.start >= max_end {
                continue;
            }

            // Clip hole end to max valid offset
            let hole_end = hole.end.min(max_end);

            // No intersection with this hole
            if frag_end <= hole.start || frag_start >= hole_end {
                new_holes.push(FragmentHole {
                    start: hole.start,
                    end: hole_end,
                });
                continue;
            }

            // Fragment must be fully inside this hole
            if frag_start < hole.start || frag_end > hole_end {
                return Err(FragmentDropReason::Overlap);
            }

            covered = true;

            // Split the hole around the fragment
            if hole.start < frag_start {
                new_holes.push(FragmentHole {
                    start: hole.start,
                    end: frag_start,
                });
            }
            if frag_end < hole_end {
                new_holes.push(FragmentHole {
                    start: frag_end,
                    end: hole_end,
                });
            }
        }

        if !covered {
            // Fragment doesn't fit in any hole - duplicate or overlap
            // Per RFC 5722, this should trigger queue discard (handled by caller)
            return Err(FragmentDropReason::Duplicate);
        }

        // === Fragment validated successfully - now commit state changes ===

        // Set last fragment flags only after validation succeeds
        // This prevents attacker-controlled total_len from persisting on failed insert
        if is_last {
            self.have_last = true;
            self.total_len = Some(frag_end);
        }

        // Sort holes by start offset
        new_holes.sort_by_key(|h| h.start);
        self.holes = new_holes;

        // Store fragment data
        self.frags.insert(offset, data.to_vec());
        self.received_frags += 1;
        self.received_bytes += len as usize;

        // Note: We do NOT refresh expiration on fragment arrival.
        // This prevents DoS by sending trickle fragments to keep queues alive indefinitely.
        // Queue expires at created_ms + FRAG_TIMEOUT_MS regardless of activity.

        // Check if reassembly is complete
        Ok(self.is_complete())
    }

    /// Check if all fragments have been received
    fn is_complete(&self) -> bool {
        self.have_first && self.have_last && self.l4_header_ok && self.holes.is_empty()
    }

    /// Reassemble the complete packet
    ///
    /// Returns None if not complete or on error.
    fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let total = self.total_len? as usize;
        if total > MAX_PACKET_SIZE {
            return None;
        }

        let mut buf = alloc::vec![0u8; total];

        for (&off, frag) in &self.frags {
            let start = off as usize;
            let end = start + frag.len();
            if end > total {
                return None; // Shouldn't happen if complete
            }
            buf[start..end].copy_from_slice(frag);
        }

        Some(buf)
    }

    /// Check if this queue has expired
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

// ============================================================================
// Fragment Cache (Global State)
// ============================================================================

/// Global fragment reassembly cache
pub struct FragmentCache {
    /// Active reassembly queues keyed by FragmentKey
    queues: Mutex<BTreeMap<FragmentKey, FragmentQueue>>,
    /// Per-source queue counts
    per_src_counts: Mutex<BTreeMap<u32, usize>>,
    /// Statistics
    stats: FragmentStats,
}

impl FragmentCache {
    /// Create a new fragment cache
    pub const fn new() -> Self {
        Self {
            queues: Mutex::new(BTreeMap::new()),
            per_src_counts: Mutex::new(BTreeMap::new()),
            stats: FragmentStats::new(),
        }
    }

    /// Process an incoming fragment
    ///
    /// Returns:
    /// - Ok(Some(payload)) if reassembly is complete
    /// - Ok(None) if more fragments needed
    /// - Err(reason) if fragment was dropped
    pub fn process_fragment(
        &self,
        header: &Ipv4Header,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, FragmentDropReason> {
        self.stats
            .fragments_received
            .fetch_add(1, Ordering::Relaxed);

        let key = FragmentKey::from_header(header);
        let src_ip = key.src_ip();

        // Fragment offset is in 8-byte units
        let offset = header.fragment_offset() * 8;
        let more_fragments = header.more_fragments();

        let mut queues = self.queues.lock();
        let mut per_src = self.per_src_counts.lock();

        // Check for expired queue on arrival and drop it
        // (Fixed queue lifetime - no extension on fragment arrival)
        if let Some(queue) = queues.get(&key) {
            if queue.is_expired(now_ms) {
                let frag_count = queue.received_frags as u32;
                let byte_count = queue.received_bytes as u64;
                queues.remove(&key);
                if let Some(c) = per_src.get_mut(&src_ip) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        per_src.remove(&src_ip);
                    }
                }
                self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                if frag_count > 0 {
                    self.stats
                        .buffered_fragments
                        .fetch_sub(frag_count, Ordering::Relaxed);
                    // R62-2 FIX: Decrement buffered bytes on arrival-time timeout
                    self.stats
                        .buffered_bytes
                        .fetch_sub(byte_count, Ordering::Relaxed);
                }
                return Err(FragmentDropReason::Timeout);
            }
        }

        // Check global limits
        let current_queues = queues.len();
        let current_frags = self.stats.buffered_fragments.load(Ordering::Relaxed) as usize;
        // R62-2 FIX: Check global byte limit
        let current_bytes = self.stats.buffered_bytes.load(Ordering::Relaxed) as usize;

        // Track whether we just created a new queue (for cleanup on error)
        let mut created_new_queue = false;

        // Get or create queue
        let queue = if let Some(q) = queues.get_mut(&key) {
            q
        } else {
            // R101-12 FIX: LRU eviction under memory pressure.
            //
            // When the global queue limit is reached, instead of simply rejecting
            // the new fragment (which drops legitimate traffic), evict the oldest
            // reassembly queue to make room. This ensures legitimate fragmented
            // packets have a chance even when an attacker is flooding with crafted
            // fragments that are never completed.
            if current_queues >= GLOBAL_MAX_QUEUES {
                // Find and evict the oldest queue (by creation time)
                let oldest_key = queues
                    .iter()
                    .min_by_key(|(_, q)| q.created_ms)
                    .map(|(&k, _)| k);

                if let Some(evict_key) = oldest_key {
                    let evict_src = evict_key.src_ip();
                    if let Some(evicted) = queues.remove(&evict_key) {
                        let frag_count = evicted.received_frags as u32;
                        let byte_count = evicted.received_bytes as u64;
                        if let Some(c) = per_src.get_mut(&evict_src) {
                            *c = c.saturating_sub(1);
                            if *c == 0 {
                                per_src.remove(&evict_src);
                            }
                        }
                        self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                        if frag_count > 0 {
                            self.stats
                                .buffered_fragments
                                .fetch_sub(frag_count, Ordering::Relaxed);
                            self.stats
                                .buffered_bytes
                                .fetch_sub(byte_count, Ordering::Relaxed);
                        }
                        self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    self.stats
                        .global_limit_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(FragmentDropReason::GlobalQueueLimit);
                }
            }
            if current_frags >= GLOBAL_MAX_FRAGS {
                self.stats
                    .global_limit_drops
                    .fetch_add(1, Ordering::Relaxed);
                return Err(FragmentDropReason::GlobalFragLimit);
            }
            // R62-2 FIX: Reject if adding this fragment would exceed global byte limit
            if current_bytes.saturating_add(payload.len()) > GLOBAL_MAX_FRAG_BYTES {
                self.stats
                    .global_limit_drops
                    .fetch_add(1, Ordering::Relaxed);
                return Err(FragmentDropReason::GlobalByteLimit);
            }

            // Check per-source limit
            let src_count = per_src.get(&src_ip).copied().unwrap_or(0);
            if src_count >= MAX_QUEUES_PER_SRC {
                self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
                return Err(FragmentDropReason::PerSourceLimit);
            }

            // Create new queue
            let new_queue = FragmentQueue::new(key, now_ms);
            queues.insert(key, new_queue);
            *per_src.entry(src_ip).or_insert(0) += 1;
            self.stats.active_queues.fetch_add(1, Ordering::Relaxed);
            created_new_queue = true;

            queues.get_mut(&key).unwrap()
        };

        // R66-11 FIX: Use atomic check-and-increment for global limits
        // This replaces the racy check-then-increment pattern with CAS operations.
        // We reserve resources BEFORE insertion, then release on failure.

        // For new queues, limits were already checked above (non-atomically is OK there
        // because we hold the queue lock and haven't committed anything yet).
        // For existing queues, we must atomically reserve.

        // R66-11 FIX: Atomically reserve fragment slot
        if !self.stats.try_reserve_fragment(GLOBAL_MAX_FRAGS) {
            // Codex review fix: Roll back queue creation on reservation failure
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&src_ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&src_ip);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
            }
            self.stats
                .global_limit_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::GlobalFragLimit);
        }

        // R66-11 FIX: Atomically reserve bytes
        if !self
            .stats
            .try_reserve_bytes(payload.len(), GLOBAL_MAX_FRAG_BYTES)
        {
            // Release the fragment slot we just reserved
            self.stats.release_fragment();

            // Codex review fix: Roll back queue creation on reservation failure
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&src_ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&src_ip);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
            }

            self.stats
                .global_limit_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::GlobalByteLimit);
        }

        // Insert fragment (resources are now reserved)
        match queue.insert(offset, more_fragments, payload, now_ms) {
            Ok(complete) => {
                // Resources already accounted for via try_reserve above

                if complete {
                    // Reassembly complete - extract data before removing queue
                    let result = queue.reassemble();
                    let frag_count = queue.received_frags as u32;
                    let byte_count = queue.received_bytes as u64;

                    // Remove queue (queue reference is now invalid)
                    queues.remove(&key);
                    if let Some(count) = per_src.get_mut(&src_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&src_ip);
                        }
                    }
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                    self.stats
                        .buffered_fragments
                        .fetch_sub(frag_count, Ordering::Relaxed);
                    // R62-2 FIX: Decrement buffered bytes on completion
                    self.stats
                        .buffered_bytes
                        .fetch_sub(byte_count, Ordering::Relaxed);
                    self.stats.reassembled.fetch_add(1, Ordering::Relaxed);

                    Ok(result)
                } else {
                    Ok(None)
                }
            }
            Err(reason) => {
                // R66-11 FIX: Release reserved resources since insert failed
                // We reserved 1 fragment slot and payload.len() bytes before insert
                self.stats.release_fragment();
                self.stats.release_bytes(payload.len());

                // RFC 5722 compliance: on overlap OR duplicate, discard the ENTIRE reassembly queue
                // Both indicate either an attack or a retransmission with different data
                if reason == FragmentDropReason::Overlap || reason == FragmentDropReason::Duplicate
                {
                    let frag_count = queue.received_frags as u32;
                    let byte_count = queue.received_bytes as u64;
                    queues.remove(&key);
                    if let Some(count) = per_src.get_mut(&src_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&src_ip);
                        }
                    }
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                    if frag_count > 0 {
                        self.stats
                            .buffered_fragments
                            .fetch_sub(frag_count, Ordering::Relaxed);
                        // R62-2 FIX: Decrement buffered bytes on queue removal
                        self.stats
                            .buffered_bytes
                            .fetch_sub(byte_count, Ordering::Relaxed);
                    }
                    self.stats.overlap_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(reason);
                }

                // FirstTooSmall on an existing queue means a malformed first fragment
                // arrived after other fragments. This is suspicious - drop the queue
                // to avoid pinning memory for 45s on a malformed packet.
                if reason == FragmentDropReason::FirstTooSmall && !created_new_queue {
                    let frag_count = queue.received_frags as u32;
                    let byte_count = queue.received_bytes as u64;
                    queues.remove(&key);
                    if let Some(count) = per_src.get_mut(&src_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&src_ip);
                        }
                    }
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                    if frag_count > 0 {
                        self.stats
                            .buffered_fragments
                            .fetch_sub(frag_count, Ordering::Relaxed);
                        // R62-2 FIX: Decrement buffered bytes on queue removal
                        self.stats
                            .buffered_bytes
                            .fetch_sub(byte_count, Ordering::Relaxed);
                    }
                    self.stats
                        .first_too_small_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(reason);
                }

                // Clean up empty queues created for invalid first fragments
                // (e.g., FirstTooSmall, ZeroLength)
                if created_new_queue && queue.received_frags == 0 {
                    queues.remove(&key);
                    if let Some(count) = per_src.get_mut(&src_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&src_ip);
                        }
                    }
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                }

                // Update appropriate counter
                match reason {
                    FragmentDropReason::RateLimited => {
                        self.stats.rate_limit_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    FragmentDropReason::FirstTooSmall => {
                        self.stats
                            .first_too_small_drops
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    FragmentDropReason::TooLarge => {
                        self.stats.too_large_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    FragmentDropReason::QueueFragLimit => {
                        self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                Err(reason)
            }
        }
    }

    /// Run timeout cleanup
    ///
    /// Should be called periodically from timer interrupt.
    /// Returns number of queues cleaned up.
    pub fn cleanup_expired(&self, now_ms: u64) -> usize {
        let mut queues = self.queues.lock();
        let mut per_src = self.per_src_counts.lock();

        let mut expired_keys = Vec::new();

        for (&key, queue) in queues.iter() {
            if queue.is_expired(now_ms) {
                // R62-2 FIX: Include byte count for cleanup
                expired_keys.push((
                    key,
                    queue.key.src_ip(),
                    queue.received_frags,
                    queue.received_bytes,
                ));
            }
        }

        let count = expired_keys.len();

        for (key, src_ip, frag_count, byte_count) in expired_keys {
            queues.remove(&key);
            if let Some(c) = per_src.get_mut(&src_ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    per_src.remove(&src_ip);
                }
            }
            self.stats.timeout_drops.fetch_add(1, Ordering::Relaxed);
            self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
            self.stats
                .buffered_fragments
                .fetch_sub(frag_count as u32, Ordering::Relaxed);
            // R62-2 FIX: Decrement buffered bytes on timeout cleanup
            self.stats
                .buffered_bytes
                .fetch_sub(byte_count as u64, Ordering::Relaxed);
        }

        count
    }

    /// Get current statistics
    pub fn stats(&self) -> &FragmentStats {
        &self.stats
    }
}

// ============================================================================
// Global Instance
// ============================================================================

static FRAGMENT_CACHE: Once<FragmentCache> = Once::new();

/// Get the global fragment cache
pub fn fragment_cache() -> &'static FragmentCache {
    FRAGMENT_CACHE.call_once(FragmentCache::new)
}

/// Process an incoming IP fragment
///
/// Convenience wrapper around fragment_cache().process_fragment()
pub fn process_fragment(
    header: &Ipv4Header,
    payload: &[u8],
    now_ms: u64,
) -> Result<Option<Vec<u8>>, FragmentDropReason> {
    fragment_cache().process_fragment(header, payload, now_ms)
}

/// Run fragment timeout cleanup
///
/// Should be called from timer interrupt handler.
pub fn cleanup_expired_fragments(now_ms: u64) -> usize {
    fragment_cache().cleanup_expired(now_ms)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::Ipv4Addr;

    fn make_header(src: [u8; 4], id: u16, offset: u16, mf: bool) -> Ipv4Header {
        let flags_frag = if mf { 0x2000 | offset } else { offset };
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_len: 0,
            identification: id,
            flags_fragment: flags_frag,
            ttl: 64,
            protocol: 17, // UDP
            checksum: 0,
            src: Ipv4Addr(src),
            dst: Ipv4Addr([192, 168, 1, 1]),
            options_len: 0,
        }
    }

    #[test]
    fn test_fragment_key() {
        let hdr = make_header([10, 0, 0, 1], 0x1234, 0, true);
        let key = FragmentKey::from_header(&hdr);
        assert_eq!(key.src, [10, 0, 0, 1]);
        assert_eq!(key.identification, 0x1234);
    }

    #[test]
    fn test_simple_reassembly() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // Fragment 1: offset 0, MF=1
        let hdr1 = make_header([10, 0, 0, 1], 0x1234, 0, true);
        let data1 = [1u8; 16]; // 16 bytes at offset 0

        // Fragment 2: offset 2 (16 bytes), MF=0
        let hdr2 = make_header([10, 0, 0, 1], 0x1234, 2, false);
        let data2 = [2u8; 16]; // 16 bytes at offset 16

        let result1 = cache.process_fragment(&hdr1, &data1, now);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none());

        let result2 = cache.process_fragment(&hdr2, &data2, now);
        assert!(result2.is_ok());
        let reassembled = result2.unwrap();
        assert!(reassembled.is_some());

        let packet = reassembled.unwrap();
        assert_eq!(packet.len(), 32);
        assert_eq!(&packet[0..16], &[1u8; 16]);
        assert_eq!(&packet[16..32], &[2u8; 16]);
    }

    #[test]
    fn test_overlap_rejection() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // Fragment 1: offset 0, 16 bytes
        let hdr1 = make_header([10, 0, 0, 1], 0x5678, 0, true);
        let data1 = [1u8; 16];

        // Fragment 2: offset 1 (8 bytes) - overlaps!
        let hdr2 = make_header([10, 0, 0, 1], 0x5678, 1, true);
        let data2 = [2u8; 16];

        let _ = cache.process_fragment(&hdr1, &data1, now);
        let result2 = cache.process_fragment(&hdr2, &data2, now);

        assert!(result2.is_err());
        assert_eq!(result2.unwrap_err(), FragmentDropReason::Overlap);
    }

    #[test]
    fn test_first_fragment_too_small() {
        let cache = FragmentCache::new();
        let now = 1000u64;

        // First fragment with only 4 bytes (less than MIN_L4_HEADER_BYTES)
        let hdr = make_header([10, 0, 0, 1], 0x9ABC, 0, true);
        let data = [1u8; 4];

        let result = cache.process_fragment(&hdr, &data, now);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FragmentDropReason::FirstTooSmall);
    }
}
