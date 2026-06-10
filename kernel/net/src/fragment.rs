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

// R169-11: per-fragment map is allocation-fallible (FallibleOrderedMap, relocated
// to the `mm` crate) so a crafted fragment stream cannot OOM-abort the kernel.
use mm::fallible_map::FallibleOrderedMap;

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

// R169-10: per-namespace fragment-reassembly ceilings = a FIXED 1/4 of each
// global budget. The cross-ns isolation goal (one netns flooding crafted
// fragments must not deny another netns reassembly) requires capping ALL THREE
// dimensions per-ns: a queue-count cap alone is insufficient because the global
// BYTE budget exhausts at 64MiB/512KiB = 128 queues and the global FRAG budget at
// 32768/64 = 512 queues — BOTH below the 1024 queue cap — so a flooder would
// exhaust the byte/frag pool below any queue cap (those rejection paths have no
// LRU recycling => renewable cross-ns starvation). Fixing each per-ns cap at 1/4
// of global guarantees >=3/4 of every global budget is ALWAYS reachable by other
// tenants, and a tenant's ceiling never shrinks as neighbors appear (a FIXED
// fraction, NOT GLOBAL/live_ns_count — which would have a shrinking-floor TOCTOU
// hazard). DOCUMENTED RESIDUAL (per-ns FAIRNESS, not the single-flooder goal): 4
// coordinated flooding namespaces each at their ceiling jointly consume the full
// 4x16MiB = 64MiB global pool and can deny a 5th — an intentional trade of
// multi-ns headroom for the non-shrinking single-tenant floor.
pub const MAX_QUEUES_PER_NS: usize = GLOBAL_MAX_QUEUES / 4; // 1024
pub const MAX_FRAGS_PER_NS: usize = GLOBAL_MAX_FRAGS / 4; // 8192
pub const MAX_BYTES_PER_NS: u64 = (GLOBAL_MAX_FRAG_BYTES as u64) / 4; // 16 MiB

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
    /// R169-10: per-namespace live-queue count ceiling reached
    PerNsQueueLimit,
    /// R169-10: per-namespace buffered-fragment ceiling reached
    PerNsFragLimit,
    /// R169-10: per-namespace buffered-byte ceiling reached
    PerNsByteLimit,
}

// ============================================================================
// Fragment Key
// ============================================================================

/// Key to identify a fragment reassembly queue
///
/// Per RFC 791, fragments are identified by (src, dst, protocol, identification).
/// R140-4 FIX: Include net_ns_id so that fragment reassembly is isolated per
/// network namespace.  Without this, overlapping private IP address spaces in
/// different namespaces can cause cross-namespace fragment injection or DoS via
/// global queue exhaustion.
/// Ord is derived to allow direct use as BTreeMap key (avoiding lossy u64 packing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragmentKey {
    /// R140-4 FIX: Network namespace ID for cross-namespace isolation.
    pub net_ns_id: u64,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub identification: u16,
}

impl FragmentKey {
    /// Create key from IPv4 header within a specific network namespace.
    pub fn from_header(net_ns_id: u64, hdr: &Ipv4Header) -> Self {
        Self {
            net_ns_id,
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
    /// Fragment data keyed by offset. R169-11: allocation-fallible map (the only
    /// no_std fallible ordered map) so an attacker's fragment stream cannot
    /// OOM-abort the kernel on a per-fragment insert.
    frags: FallibleOrderedMap<u16, Vec<u8>>,
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
    /// R169-11: fallible constructor — the initial single-hole `Vec` is reserved
    /// via `try_reserve_exact` so an OOM here returns `Err(QueueByteLimit)` instead
    /// of aborting the kernel. The caller propagates the error WITHOUT charging any
    /// counter (the queue was never inserted), so accounting stays balanced.
    fn new(key: FragmentKey, now_ms: u64) -> Result<Self, FragmentDropReason> {
        let mut holes: Vec<FragmentHole> = Vec::new();
        holes
            .try_reserve_exact(1)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        // Initial hole: entire possible packet range (capacity reserved above).
        holes.push(FragmentHole {
            start: 0,
            end: u16::MAX,
        });
        Ok(Self {
            key,
            created_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(FRAG_TIMEOUT_MS),
            total_len: None,
            received_frags: 0,
            received_bytes: 0,
            holes,
            frags: FallibleOrderedMap::new(),
            have_first: false,
            have_last: false,
            l4_header_ok: false,
            rate_limiter: RateLimiter::new(now_ms),
        })
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
        // R102-L1 FIX: Use checked conversion instead of silent truncation.
        // Upstream callers enforce MTU limits, but defense-in-depth rejects
        // oversized data that would silently wrap to a smaller u16 value.
        let len = u16::try_from(data.len()).map_err(|_| FragmentDropReason::TooLarge)?;

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
            for (&stored_off, stored_data) in self.frags.iter() {
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

        // RFC 815 hole algorithm: fragment must fill part of a hole.
        // R169-11 (transactional, OOM-safe): reserve the new-holes buffer BEFORE
        // touching `self.holes`, and iterate `self.holes` by COPY (FragmentHole is
        // `Copy`) instead of `drain(..)`. So if the `try_reserve` here — or the
        // payload copy / `try_insert` below — fails under memory pressure, the
        // ACCOUNTING-critical queue state (`holes`, `frags`, `total_len`,
        // `have_last`, `received_frags`/`received_bytes`) is left unchanged and we
        // return `Err(QueueByteLimit)`. (The first-fragment `have_first`/
        // `l4_header_ok` flags and the rate-limiter token are updated earlier, but
        // that does NOT affect retry correctness: the offset-0 hole is still
        // present, so `is_complete()` cannot mis-fire and a retry of the same
        // fragment re-inserts normally.)
        let mut new_holes: Vec<FragmentHole> = Vec::new();
        new_holes
            .try_reserve(self.holes.len() + 1)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        let mut covered = false;

        for hole in self.holes.iter().copied() {
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

            // Split the hole around the fragment. Bound proof: exactly one hole is
            // `covered` (yields <=2 outputs, consuming 1) and every other hole
            // yields <=1, so total pushes <= self.holes.len() + 1 — the reserved
            // capacity — and these pushes therefore never reallocate.
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
            // Per RFC 5722, this should trigger queue discard (handled by caller).
            // `self` is still unmutated (drain replaced by copy-iteration).
            return Err(FragmentDropReason::Duplicate);
        }

        // === Fragment validated. R169-11: perform ALL fallible allocation FIRST,
        // then commit the accounting-critical state — so an OOM cannot leave the
        // queue's hole list / stored fragments / byte+frag counts half-mutated
        // (the offset-0 hole + counters stay consistent, so a retry is correct). ===

        // 1. Payload copy — fallible (attacker-sized up to the fragment MTU). The
        //    capacity is reserved exactly, so `extend_from_slice` cannot reallocate.
        let mut frag_data: Vec<u8> = Vec::new();
        frag_data
            .try_reserve_exact(data.len())
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;
        frag_data.extend_from_slice(data);

        // 2. Fallible ordered-map insert (FallibleOrderedMap::try_insert reserves
        //    its backing Vec before the shift; on Err the map is unchanged).
        //    Offset uniqueness was established by the overlap checks above.
        self.frags
            .try_insert(offset, frag_data)
            .map_err(|_| FragmentDropReason::QueueByteLimit)?;

        // 3. COMMIT — all infallible from here; the accounting-critical state
        //    (holes/frags/total_len/have_last/received_*) was untouched until now.
        //    Deferring the is_last/total_len write past the fallible steps is what
        //    keeps the insert transactional (a retry after an OOM here must not see
        //    a stale `total_len`/`have_last` with no stored fragment).
        if is_last {
            self.have_last = true;
            self.total_len = Some(frag_end);
        }
        new_holes.sort_by_key(|h| h.start);
        self.holes = new_holes;
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

        // R169-11: fallible output allocation — `total` is attacker-influenced (up
        // to MAX_PACKET_SIZE). On OOM return `None` (folds into the existing
        // `Option<Vec<u8>>` contract); the completion-boundary caller treats a
        // `None` here as an OOM drop and still fully unwinds the queue's charges.
        let mut buf: Vec<u8> = Vec::new();
        if buf.try_reserve_exact(total).is_err() {
            return None;
        }
        buf.resize(total, 0); // capacity reserved above → no reallocation

        for (&off, frag) in self.frags.iter() {
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
    /// R141-2 FIX: Per-source queue counts, scoped by (net_ns_id, src_ip).
    /// Previously keyed by src_ip alone; one namespace's fragment traffic
    /// could exhaust the per-source budget for all namespaces sharing the
    /// same source IP (cross-namespace DoS).
    per_src_counts: Mutex<BTreeMap<(u64, u32), usize>>,
    /// R169-10: per-netns fragment budget counts (queues / frags / bytes). The
    /// INNERMOST reassembly lock — order: `queues` -> `per_src_counts` ->
    /// `per_ns_counts`. An entry exists only while a namespace holds >=1 live
    /// queue (or any buffered frag/byte) and is pruned when all three reach 0, so
    /// the map stays bounded by the live-namespace count. Plain `BTreeMap` (NOT
    /// `FallibleOrderedMap`): the value is a 24-byte `PerNsBudget` and its node
    /// alloc is the same bounded AD-02 residual class as `per_src.entry`, gated by
    /// the admission caps checked immediately above it.
    per_ns_counts: Mutex<BTreeMap<u64, PerNsBudget>>,
    /// Statistics
    stats: FragmentStats,
}

/// R169-10: a namespace's contribution to the three global fragment budgets.
/// `sum(per_ns) == global` is maintained as an invariant across every charge /
/// release site (asserted by `run_fragment_perns_self_test`).
#[derive(Debug, Default, Clone, Copy)]
struct PerNsBudget {
    /// live reassembly queues owned by this namespace (mirrors active_queues)
    queues: usize,
    /// buffered fragments charged to this namespace (mirrors buffered_fragments)
    frags: u32,
    /// buffered bytes charged to this namespace (mirrors buffered_bytes)
    bytes: u64,
}

// R169-10: per-ns budget mutators. Free functions over the held guard's map so
// they never re-enter the lock. `*_charge_*` use `entry().or_default()`; `*_release_*`
// saturating-sub then prune. PRUNE ONLY when ALL THREE fields are 0 (a live queue
// implies `queues >= 1`, so an entry is never dropped while a queue lives — which
// keeps `entry()`/`get()` for an existing queue's frag/byte charge consistent).
fn per_ns_charge_queue(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64) {
    m.entry(ns).or_default().queues += 1;
}
fn per_ns_charge_frag(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64) {
    m.entry(ns).or_default().frags += 1;
}
fn per_ns_charge_bytes(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64, b: u64) {
    m.entry(ns).or_default().bytes += b;
}
fn per_ns_prune_if_zero(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64) {
    if let Some(e) = m.get(&ns) {
        if e.queues == 0 && e.frags == 0 && e.bytes == 0 {
            m.remove(&ns);
        }
    }
}
fn per_ns_release_queue(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64) {
    if let Some(e) = m.get_mut(&ns) {
        e.queues = e.queues.saturating_sub(1);
    }
    per_ns_prune_if_zero(m, ns);
}
fn per_ns_release_frags(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64, n: u32) {
    if let Some(e) = m.get_mut(&ns) {
        e.frags = e.frags.saturating_sub(n);
    }
    per_ns_prune_if_zero(m, ns);
}
fn per_ns_release_bytes(m: &mut BTreeMap<u64, PerNsBudget>, ns: u64, b: u64) {
    if let Some(e) = m.get_mut(&ns) {
        e.bytes = e.bytes.saturating_sub(b);
    }
    per_ns_prune_if_zero(m, ns);
}

impl FragmentCache {
    /// Create a new fragment cache
    pub const fn new() -> Self {
        Self {
            queues: Mutex::new(BTreeMap::new()),
            per_src_counts: Mutex::new(BTreeMap::new()),
            per_ns_counts: Mutex::new(BTreeMap::new()),
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
        net_ns_id: u64,
        header: &Ipv4Header,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, FragmentDropReason> {
        self.stats
            .fragments_received
            .fetch_add(1, Ordering::Relaxed);

        // R140-4 FIX: Include net_ns_id in key to isolate reassembly per namespace.
        let key = FragmentKey::from_header(net_ns_id, header);
        let src_ip = key.src_ip();
        // R141-2 FIX: Namespace-scoped per-source key replaces bare src_ip.
        let per_src_key = (key.net_ns_id, src_ip);

        // Fragment offset is in 8-byte units
        let offset = header.fragment_offset() * 8;
        let more_fragments = header.more_fragments();

        // R163-27 / R169-10 FIX: Document lock ordering — `queues` before
        // `per_src_counts` before `per_ns_counts` (innermost leaf). Always acquired
        // in this order; never reverse. All three held for the whole critical
        // section, acquired once up front, never re-locked.
        let mut queues = self.queues.lock();
        let mut per_src = self.per_src_counts.lock();
        let mut per_ns = self.per_ns_counts.lock();

        // Check for expired queue on arrival and drop it
        // (Fixed queue lifetime - no extension on fragment arrival)
        if let Some(queue) = queues.get(&key) {
            if queue.is_expired(now_ms) {
                let frag_count = queue.received_frags as u32;
                let byte_count = queue.received_bytes as u64;
                queues.remove(&key);
                if let Some(c) = per_src.get_mut(&per_src_key) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        per_src.remove(&per_src_key);
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
                // R169-10 R0: release the expired queue's per-ns charges (this ns).
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
                if frag_count > 0 {
                    per_ns_release_frags(&mut per_ns, key.net_ns_id, frag_count);
                    per_ns_release_bytes(&mut per_ns, key.net_ns_id, byte_count);
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
            // R169-10: per-ns admission gate — the SECURITY CRUX. Checked FIRST in
            // the create branch (BEFORE the global-LRU eviction below), so a
            // flooding tenant hits its OWN per-ns ceiling and returns Err before LRU
            // victim-selection can run — it can never evict another namespace's
            // in-flight queue. ns 0 (root) is cap-EXEMPT here but is still
            // charged/released below so `sum(per_ns) == global` holds. The per-ns
            // FRAG and BYTE ceilings are ALSO enforced at the reserve sites (C2/C3)
            // for existing queues; this create-branch check covers the queue count
            // (mutated only on create/teardown) and gives an early frag/byte reject.
            if key.net_ns_id != 0 {
                let nb = per_ns.get(&key.net_ns_id).copied().unwrap_or_default();
                if nb.queues >= MAX_QUEUES_PER_NS {
                    self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(FragmentDropReason::PerNsQueueLimit);
                }
                if (nb.frags as usize) >= MAX_FRAGS_PER_NS {
                    self.stats.global_limit_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(FragmentDropReason::PerNsFragLimit);
                }
                if nb.bytes.saturating_add(payload.len() as u64) > MAX_BYTES_PER_NS {
                    self.stats.global_limit_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(FragmentDropReason::PerNsByteLimit);
                }
            }

            // R101-12 FIX: LRU eviction under memory pressure.
            //
            // When the global queue limit is reached, instead of simply rejecting
            // the new fragment (which drops legitimate traffic), evict the oldest
            // reassembly queue to make room. This ensures legitimate fragmented
            // packets have a chance even when an attacker is flooding with crafted
            // fragments that are never completed.
            if current_queues >= GLOBAL_MAX_QUEUES {
                // Find and evict the oldest queue (by creation time).
                // R169-10: SAME-NS filter — only the arriving fragment's OWN
                // namespace is an eviction candidate, so a tenant can cannibalize
                // only its own oldest queue, never another ns's. (With the per-ns
                // queue cap above, a single flooder is already rejected at 1024
                // before reaching here; this filter is cheap defense-in-depth.)
                let oldest_key = queues
                    .iter()
                    .filter(|(k, _)| k.net_ns_id == key.net_ns_id)
                    .min_by_key(|(_, q)| q.created_ms)
                    .map(|(&k, _)| k);

                if let Some(evict_key) = oldest_key {
                    // R141-2 FIX: Use namespace-scoped key for eviction path.
                    let evict_per_src_key = (evict_key.net_ns_id, evict_key.src_ip());
                    if let Some(evicted) = queues.remove(&evict_key) {
                        let frag_count = evicted.received_frags as u32;
                        let byte_count = evicted.received_bytes as u64;
                        if let Some(c) = per_src.get_mut(&evict_per_src_key) {
                            *c = c.saturating_sub(1);
                            if *c == 0 {
                                per_src.remove(&evict_per_src_key);
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
                        // R169-10 R8: release the VICTIM's per-ns charges. MUST key
                        // off evict_key.net_ns_id (the victim), NOT key.net_ns_id —
                        // the same-ns filter makes them equal today, but keying off
                        // the victim is correct/robust if any path ever evicts
                        // cross-ns.
                        per_ns_release_queue(&mut per_ns, evict_key.net_ns_id);
                        if frag_count > 0 {
                            per_ns_release_frags(&mut per_ns, evict_key.net_ns_id, frag_count);
                            per_ns_release_bytes(&mut per_ns, evict_key.net_ns_id, byte_count);
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
            let src_count = per_src.get(&per_src_key).copied().unwrap_or(0);
            if src_count >= MAX_QUEUES_PER_SRC {
                self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
                return Err(FragmentDropReason::PerSourceLimit);
            }

            // Create new queue. R169-11: the constructor is now fallible — on OOM
            // building the initial hole list, propagate the error BEFORE charging
            // any counter (the queue is never inserted, per_src/active_queues never
            // bumped), so accounting stays balanced with nothing to roll back.
            let new_queue = match FragmentQueue::new(key, now_ms) {
                Ok(q) => q,
                Err(reason) => {
                    self.stats.queue_limit_drops.fetch_add(1, Ordering::Relaxed);
                    return Err(reason);
                }
            };
            // Carried-forward residual (AD-02): `queues.insert` and `per_src.entry`
            // / `per_ns.entry` are infallible `BTreeMap` node allocations (no no_std
            // fallible BTreeMap). These are SMALL fixed-size nodes, bounded by the
            // per-ns + per-src (MAX_QUEUES_PER_SRC) + global (GLOBAL_MAX_QUEUES)
            // admission caps checked just above. R169-10/D-2 DELIBERATELY does NOT
            // migrate `queues` to a `Vec`-backed FallibleOrderedMap: each `queues`
            // value is a LARGE FragmentQueue (holes Vec + frags map + counters), so
            // a Vec-backed map's O(n) element-shift on every insert/remove would
            // convert this DoS-pressured per-packet fast path from O(log n) to O(n)
            // — the cure is worse than the bounded-small-node disease. If fallible
            // queue insertion is ever needed, use a NODE-allocating fallible map to
            // keep O(log n) + pointer stability.
            queues.insert(key, new_queue);
            *per_src.entry(per_src_key).or_insert(0) += 1;
            self.stats.active_queues.fetch_add(1, Ordering::Relaxed);
            // R169-10 C1: charge this ns's per-ns queue count (paired with the
            // active_queues++ above). Unconditional for all ns (admission already
            // guaranteed headroom for ns!=0; ns 0 is charged though cap-exempt).
            per_ns_charge_queue(&mut per_ns, key.net_ns_id);
            created_new_queue = true;

            queues.get_mut(&key).unwrap()
        };

        // R66-11 FIX: Use atomic check-and-increment for global limits
        // This replaces the racy check-then-increment pattern with CAS operations.
        // We reserve resources BEFORE insertion, then release on failure.

        // For new queues, limits were already checked above (non-atomically is OK there
        // because we hold the queue lock and haven't committed anything yet).
        // For existing queues, we must atomically reserve.

        // R169-10 C2: enforce the per-ns FRAG ceiling (ns!=0, for ALL queues
        // new+existing — an existing-queue fragment pump must also be bounded)
        // BEFORE the global atomic reserve, so a flooder hits its own ceiling first.
        // On exceed, roll back a just-created queue incl. its C1 per-ns charge (R1).
        if key.net_ns_id != 0
            && per_ns
                .get(&key.net_ns_id)
                .map(|b| b.frags as usize)
                .unwrap_or(0)
                >= MAX_FRAGS_PER_NS
        {
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&per_src_key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&per_src_key);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
            }
            self.stats.global_limit_drops.fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::PerNsFragLimit);
        }
        // R66-11 FIX: Atomically reserve fragment slot
        if !self.stats.try_reserve_fragment(GLOBAL_MAX_FRAGS) {
            // Codex review fix: Roll back queue creation on reservation failure (R1).
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&per_src_key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&per_src_key);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
            }
            self.stats
                .global_limit_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::GlobalFragLimit);
        }
        // R169-10 C2 commit: charge the per-ns frag ONLY after the global reserve
        // succeeded — a global-reserve failure then has nothing per-ns to leak.
        per_ns_charge_frag(&mut per_ns, key.net_ns_id);

        // R169-10 C3: enforce the per-ns BYTE ceiling (ns!=0) BEFORE the global byte
        // reserve. On exceed, UNDO C2 (release the global frag slot + the per-ns frag
        // charge) and roll back a just-created queue incl. its C1 per-ns charge (R2).
        if key.net_ns_id != 0
            && per_ns
                .get(&key.net_ns_id)
                .map(|b| b.bytes)
                .unwrap_or(0)
                .saturating_add(payload.len() as u64)
                > MAX_BYTES_PER_NS
        {
            self.stats.release_fragment();
            per_ns_release_frags(&mut per_ns, key.net_ns_id, 1);
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&per_src_key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&per_src_key);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
            }
            self.stats.global_limit_drops.fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::PerNsByteLimit);
        }
        // R66-11 FIX: Atomically reserve bytes
        if !self
            .stats
            .try_reserve_bytes(payload.len(), GLOBAL_MAX_FRAG_BYTES)
        {
            // Release the global fragment slot we reserved AND undo the C2 per-ns
            // frag charge (R2). Both are UNCONDITIONAL (C2 charged for all ns).
            self.stats.release_fragment();
            per_ns_release_frags(&mut per_ns, key.net_ns_id, 1);

            // Codex review fix: Roll back queue creation on reservation failure.
            if created_new_queue {
                queues.remove(&key);
                if let Some(count) = per_src.get_mut(&per_src_key) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        per_src.remove(&per_src_key);
                    }
                }
                self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                per_ns_release_queue(&mut per_ns, key.net_ns_id);
            }

            self.stats
                .global_limit_drops
                .fetch_add(1, Ordering::Relaxed);
            return Err(FragmentDropReason::GlobalByteLimit);
        }
        // R169-10 C3 commit: charge the per-ns bytes ONLY after the global reserve
        // succeeded.
        per_ns_charge_bytes(&mut per_ns, key.net_ns_id, payload.len() as u64);

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
                    if let Some(count) = per_src.get_mut(&per_src_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&per_src_key);
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
                    // R169-10 R3: whole-queue per-ns release, UNCONDITIONAL (mirrors
                    // the unguarded global completion sub above — runs whether
                    // reassemble() returned Some or None/OOM). The per-call C2/C3
                    // charges were folded into received_frags/received_bytes by the
                    // successful inserts, so this whole-queue release balances them.
                    per_ns_release_queue(&mut per_ns, key.net_ns_id);
                    per_ns_release_frags(&mut per_ns, key.net_ns_id, frag_count);
                    per_ns_release_bytes(&mut per_ns, key.net_ns_id, byte_count);
                    // R169-11: the whole-queue uncharge above (queues.remove +
                    // per_src-- + active_queues/buffered_fragments/buffered_bytes
                    // decrements) is UNCONDITIONAL once `complete` — it runs whether
                    // or not `reassemble()` succeeded, so an OOM in the reassembly
                    // output never strands the queue's bytes/frags/active_queues (the
                    // permanent-counter-climb DoS the QA flagged). Only the success
                    // bookkeeping is gated on the allocation: a `None` here is an
                    // OOM drop (reassemble() reserved its output fallibly), so count
                    // it as a global-limit drop, NOT a reassembly.
                    match result {
                        Some(buf) => {
                            self.stats.reassembled.fetch_add(1, Ordering::Relaxed);
                            Ok(Some(buf))
                        }
                        None => {
                            self.stats.global_limit_drops.fetch_add(1, Ordering::Relaxed);
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            Err(reason) => {
                // R66-11 FIX: Release reserved resources since insert failed
                // We reserved 1 fragment slot and payload.len() bytes before insert
                self.stats.release_fragment();
                self.stats.release_bytes(payload.len());
                // R169-10 R4: undo THIS failed fragment's C2/C3 per-ns charges,
                // UNCONDITIONAL (to reach this arm both global reserves committed, so
                // both C2 and C3 committed their per-ns charges). DISJOINT from R5/R6
                // below: the failed fragment was rejected by queue.insert and never
                // folded into the queue's received_frags/received_bytes, so R4 (this
                // frag) and R5/R6 (the queue's prior committed contents) release
                // different magnitudes — do NOT collapse them.
                per_ns_release_frags(&mut per_ns, key.net_ns_id, 1);
                per_ns_release_bytes(&mut per_ns, key.net_ns_id, payload.len() as u64);

                // RFC 5722 compliance: on overlap OR duplicate, discard the ENTIRE reassembly queue
                // Both indicate either an attack or a retransmission with different data
                if reason == FragmentDropReason::Overlap || reason == FragmentDropReason::Duplicate
                {
                    let frag_count = queue.received_frags as u32;
                    let byte_count = queue.received_bytes as u64;
                    queues.remove(&key);
                    if let Some(count) = per_src.get_mut(&per_src_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&per_src_key);
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
                    // R169-10 R5: release the discarded queue's PRIOR committed
                    // contents (disjoint from R4's failed frag). queue unconditional;
                    // frags/bytes gated fc>0 (mirror the global sub above).
                    per_ns_release_queue(&mut per_ns, key.net_ns_id);
                    if frag_count > 0 {
                        per_ns_release_frags(&mut per_ns, key.net_ns_id, frag_count);
                        per_ns_release_bytes(&mut per_ns, key.net_ns_id, byte_count);
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
                    if let Some(count) = per_src.get_mut(&per_src_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&per_src_key);
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
                    // R169-10 R6: release the discarded queue's prior committed
                    // contents (reached only when !created_new_queue, existing guard).
                    per_ns_release_queue(&mut per_ns, key.net_ns_id);
                    if frag_count > 0 {
                        per_ns_release_frags(&mut per_ns, key.net_ns_id, frag_count);
                        per_ns_release_bytes(&mut per_ns, key.net_ns_id, byte_count);
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
                    if let Some(count) = per_src.get_mut(&per_src_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            per_src.remove(&per_src_key);
                        }
                    }
                    self.stats.active_queues.fetch_sub(1, Ordering::Relaxed);
                    // R169-10 R7: queue-only per-ns release (received_frags == 0, so
                    // no committed frags/bytes — the failed frag was released by R4).
                    per_ns_release_queue(&mut per_ns, key.net_ns_id);
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
        // R169-10: same lock order as process_fragment (queues -> per_src -> per_ns).
        let mut queues = self.queues.lock();
        let mut per_src = self.per_src_counts.lock();
        let mut per_ns = self.per_ns_counts.lock();

        let mut expired_keys = Vec::new();

        for (&key, queue) in queues.iter() {
            if queue.is_expired(now_ms) {
                // R169-11: fallible scratch push — under memory pressure, defer the
                // remaining expired queues to the NEXT sweep rather than aborting.
                // No counter is touched until the removal loop below, so a deferral
                // leaks nothing (the still-expired queues are reclaimed next tick).
                if expired_keys.try_reserve(1).is_err() {
                    break;
                }
                // R62-2 FIX: Include byte count for cleanup
                // R141-2 FIX: Use namespace-scoped per-source key.
                expired_keys.push((
                    key,
                    (key.net_ns_id, queue.key.src_ip()),
                    queue.received_frags,
                    queue.received_bytes,
                ));
            }
        }

        let count = expired_keys.len();

        for (key, per_src_key, frag_count, byte_count) in expired_keys {
            queues.remove(&key);
            if let Some(c) = per_src.get_mut(&per_src_key) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    per_src.remove(&per_src_key);
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
            // R169-10 R9: per-ns release for each expired queue (its ns is
            // per_src_key.0). Unguarded — saturating_sub tolerates a 0-frag queue.
            per_ns_release_queue(&mut per_ns, per_src_key.0);
            per_ns_release_frags(&mut per_ns, per_src_key.0, frag_count as u32);
            per_ns_release_bytes(&mut per_ns, per_src_key.0, byte_count as u64);
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
/// R140-4 FIX: Requires network namespace ID for per-namespace isolation.
pub fn process_fragment(
    net_ns_id: u64,
    header: &Ipv4Header,
    payload: &[u8],
    now_ms: u64,
) -> Result<Option<Vec<u8>>, FragmentDropReason> {
    fragment_cache().process_fragment(net_ns_id, header, payload, now_ms)
}

/// Run fragment timeout cleanup
///
/// Should be called from timer interrupt handler.
pub fn cleanup_expired_fragments(now_ms: u64) -> usize {
    fragment_cache().cleanup_expired(now_ms)
}

/// R169-10: in-kernel self-test for the per-ns fragment triple-budget. Proves the
/// load-bearing `sum(per_ns) == global` invariant across the create / complete /
/// timeout release paths (R3, R9, C1/C2/C3), the per-ns prune, and the cross-ns
/// isolation gate (one ns at its QUEUE ceiling is rejected with `PerNsQueueLimit`
/// — fired ABOVE the global-LRU branch — while another ns still reassembles
/// normally). Runs against a LOCAL `FragmentCache`; wired into the boot suite.
pub fn run_fragment_perns_self_test() {
    fn hdr(src: [u8; 4], id: u16, offset: u16, mf: bool) -> Ipv4Header {
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_len: 0,
            identification: id,
            flags_fragment: if mf { 0x2000 | offset } else { offset },
            ttl: 64,
            protocol: 17, // UDP
            checksum: 0,
            src: crate::ipv4::Ipv4Addr(src),
            dst: crate::ipv4::Ipv4Addr([192, 168, 1, 1]),
            options_len: 0,
        }
    }
    // sum(per_ns) == the three global atomics — the invariant every charge/release
    // site must preserve. A single missed/duplicated per-ns op breaks this.
    fn assert_balanced(c: &FragmentCache, ctx: &str) {
        let pn = c.per_ns_counts.lock();
        let mut q = 0usize;
        let mut f = 0u64;
        let mut b = 0u64;
        for v in pn.values() {
            q += v.queues;
            f += v.frags as u64;
            b += v.bytes;
        }
        let gq = c.stats.active_queues.load(Ordering::Relaxed) as usize;
        let gf = c.stats.buffered_fragments.load(Ordering::Relaxed) as u64;
        let gb = c.stats.buffered_bytes.load(Ordering::Relaxed);
        assert!(
            q == gq && f == gf && b == gb,
            "R169-10 balance [{}]: per_ns(q={},f={},b={}) != global(q={},f={},b={})",
            ctx, q, f, b, gq, gf, gb
        );
    }

    let cache = FragmentCache::new();
    let (ns_a, ns_b) = (10u64, 20u64);
    let payload = [0u8; 64]; // >= MIN_L4_HEADER_BYTES

    // (1) create one incomplete queue in each ns (offset 0, MF=1 -> 1 buffered frag).
    assert!(matches!(
        cache.process_fragment(ns_a, &hdr([10, 0, 0, 1], 1, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_balanced(&cache, "A create");
    assert!(matches!(
        cache.process_fragment(ns_b, &hdr([20, 0, 0, 1], 1, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_balanced(&cache, "B create");
    {
        let pn = cache.per_ns_counts.lock();
        assert_eq!(
            pn.get(&ns_a).map(|v| (v.queues, v.frags, v.bytes)),
            Some((1, 1, 64)),
            "R169-10: ns A charged 1 queue / 1 frag / 64 bytes"
        );
    }

    // (1b) ROOT namespace (ns 0): cap-EXEMPT at admission / C2 / C3, but STILL
    // charged AND released, so the `sum(per_ns) == global` invariant must hold for
    // the ns-0 entry too. (Its release is covered by the timeout sweep in step 4.)
    assert!(matches!(
        cache.process_fragment(0, &hdr([1, 1, 1, 1], 7, 0, true), &payload, 0),
        Ok(None)
    ));
    assert_eq!(
        cache
            .per_ns_counts
            .lock()
            .get(&0)
            .map(|v| (v.queues, v.frags, v.bytes)),
        Some((1, 1, 64)),
        "R169-10: root ns 0 IS charged (cap-exempt but fully accounted)"
    );
    assert_balanced(&cache, "root ns 0 charged");

    // (2) complete A (offset 8*8=64, MF=0 fills [64,128)) -> R3 whole-queue release.
    assert!(matches!(
        cache.process_fragment(ns_a, &hdr([10, 0, 0, 1], 1, 8, false), &payload, 0),
        Ok(Some(_))
    ));
    assert_balanced(&cache, "A complete");
    assert!(
        cache.per_ns_counts.lock().get(&ns_a).is_none(),
        "R169-10: ns A pruned after completion (R3 + prune-at-zero)"
    );

    // (3) overlap-discard (exercises R4 + R5, the subtlest accounting): create a
    // fresh ns B queue, then send an OVERLAPPING fragment for it. The Err arm
    // releases BOTH the failed fragment's per-ns C2/C3 charges (R4) AND the queue's
    // prior committed contents (R5) — disjoint magnitudes that must both balance.
    // Heap-light (a couple of 64-byte fragments), unlike a queue-cap test which
    // would need MAX_QUEUES_PER_NS=1024 live queues (cap correctness is simple
    // arithmetic, covered by review). ns A is untouched, proving per-ns isolation.
    assert!(matches!(
        cache.process_fragment(ns_b, &hdr([20, 0, 0, 2], 2, 0, true), &payload, 0),
        Ok(None)
    ));
    assert!(
        matches!(
            cache.process_fragment(ns_b, &hdr([20, 0, 0, 2], 2, 0, true), &payload, 0),
            Err(FragmentDropReason::Overlap) | Err(FragmentDropReason::Duplicate)
        ),
        "R169-10: an overlapping fragment discards the queue (R4 + R5 release)"
    );
    assert_balanced(&cache, "B overlap-discard (R4 + R5)");

    // (4) timeout sweep -> R9 drains every queue; per_ns map empties, globals -> 0.
    cache.cleanup_expired(FRAG_TIMEOUT_MS + 1);
    assert_balanced(&cache, "after timeout sweep");
    assert!(
        cache.per_ns_counts.lock().is_empty()
            && cache.stats.active_queues.load(Ordering::Relaxed) == 0
            && cache.stats.buffered_bytes.load(Ordering::Relaxed) == 0,
        "R169-10: per_ns + globals fully drained after the timeout sweep"
    );
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
        // R140-4 FIX: FragmentKey now includes net_ns_id
        let key = FragmentKey::from_header(42, &hdr);
        assert_eq!(key.net_ns_id, 42);
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

        let result1 = cache.process_fragment(1, &hdr1, &data1, now);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none());

        let result2 = cache.process_fragment(1, &hdr2, &data2, now);
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

        let _ = cache.process_fragment(1, &hdr1, &data1, now);
        let result2 = cache.process_fragment(1, &hdr2, &data2, now);

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

        let result = cache.process_fragment(1, &hdr, &data, now);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), FragmentDropReason::FirstTooSmall);
    }
}
