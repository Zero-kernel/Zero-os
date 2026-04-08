//! VirtQueue implementation for Zero-OS
//!
//! This module provides a generic virtqueue implementation that can be shared
//! across different VirtIO device drivers (block, network, etc.).

use alloc::vec;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

use crate::{rmb, wmb, VringAvail, VringDesc, VringUsed, VringUsedElem};

/// Generic virtqueue implementation shared by VirtIO drivers.
///
/// This provides the core virtqueue functionality including:
/// - Descriptor allocation/deallocation
/// - Available ring management
/// - Used ring polling
pub struct VirtQueue {
    /// Queue size (number of descriptors).
    size: u16,
    /// Queue notify offset (for PCI transport).
    notify_off: u16,
    /// Descriptor table (DMA-able memory).
    desc: *mut VringDesc,
    /// Available ring.
    avail: *mut VringAvail,
    /// Used ring.
    used: *mut VringUsed,
    /// Free descriptor stack.
    free_list: Mutex<Vec<u16>>,
    /// R44-8 FIX: Allocation bitmap to track which descriptors are in use.
    /// Prevents freeing descriptors that were never allocated (forged next pointers).
    alloc_bitmap: Mutex<Vec<bool>>,
    /// Last seen used index.
    last_used_idx: AtomicU16,
    /// Physical address of descriptor table.
    desc_phys: u64,
    /// Physical address of available ring.
    avail_phys: u64,
    /// Physical address of used ring.
    used_phys: u64,
}

// SAFETY: VirtQueue contains raw pointers to DMA-able memory
// which is only accessed within synchronized contexts.
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Calculate the total DMA memory needed for a virtqueue (bytes).
    ///
    /// Returns the size needed for descriptor table, available ring, and used ring,
    /// each aligned to 4KB for DMA compatibility.
    pub fn layout_size(queue_size: u16) -> usize {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize; // flags + idx + ring
        let used_size = 4 + 8 * queue_size as usize; // flags + idx + ring

        // Align each section to 4KB for DMA
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;
        let used_pages = (used_size + 4095) / 4096;

        (desc_pages + avail_pages + used_pages) * 4096
    }

    /// Create a new virtqueue at the given physical base address.
    ///
    /// # Arguments
    /// * `base_phys` - Physical address of the DMA buffer for the queue
    /// * `queue_size` - Number of descriptors in the queue
    /// * `phys_to_virt_offset` - Offset to convert physical to virtual address
    /// * `notify_off` - Notify offset for this queue (from transport)
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The memory region at `base_phys` is valid, DMA-able, and mapped
    /// - The region is large enough (use `layout_size()` to calculate)
    pub unsafe fn new(
        base_phys: u64,
        queue_size: u16,
        phys_to_virt_offset: u64,
        notify_off: u16,
    ) -> Self {
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 4 + 2 * queue_size as usize;

        // Calculate aligned offsets
        let desc_pages = (desc_size + 4095) / 4096;
        let avail_pages = (avail_size + 4095) / 4096;

        let desc_phys = base_phys;
        let avail_phys = desc_phys + (desc_pages * 4096) as u64;
        let used_phys = avail_phys + (avail_pages * 4096) as u64;

        // Convert to virtual addresses using the provided mapping offset
        let desc = (desc_phys + phys_to_virt_offset) as *mut VringDesc;
        let avail = (avail_phys + phys_to_virt_offset) as *mut VringAvail;
        let used = (used_phys + phys_to_virt_offset) as *mut VringUsed;

        // Initialize free list (push in reverse order so 0 is first to be allocated)
        let mut free_list = Vec::with_capacity(queue_size as usize);
        for i in (0..queue_size).rev() {
            free_list.push(i);
        }

        // R44-8 FIX: Initialize allocation bitmap (all descriptors start as free)
        let alloc_bitmap = vec![false; queue_size as usize];

        // R44-4 FIX: Zero out ALL ring memory, not just the header structs
        // This prevents info leaks from stale memory and ensures consistent state.
        // Descriptor table: queue_size * sizeof(VringDesc)
        core::ptr::write_bytes(desc, 0, queue_size as usize);
        // Available ring: flags(2) + idx(2) + ring(2 * queue_size) + used_event(2)
        let avail_bytes = 4 + 2 * queue_size as usize + 2;
        core::ptr::write_bytes(avail as *mut u8, 0, avail_bytes);
        // Used ring: flags(2) + idx(2) + ring(8 * queue_size) + avail_event(2)
        let used_bytes = 4 + 8 * queue_size as usize + 2;
        core::ptr::write_bytes(used as *mut u8, 0, used_bytes);

        Self {
            size: queue_size,
            notify_off,
            desc,
            avail,
            used,
            free_list: Mutex::new(free_list),
            alloc_bitmap: Mutex::new(alloc_bitmap),
            last_used_idx: AtomicU16::new(0),
            desc_phys,
            avail_phys,
            used_phys,
        }
    }

    /// Queue size (number of descriptors).
    #[inline]
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Notify offset for this queue (PCI transport).
    #[inline]
    pub fn notify_offset(&self) -> u16 {
        self.notify_off
    }

    /// Physical address of the descriptor table.
    #[inline]
    pub fn desc_table_phys(&self) -> u64 {
        self.desc_phys
    }

    /// Physical address of the available ring.
    #[inline]
    pub fn avail_ring_phys(&self) -> u64 {
        self.avail_phys
    }

    /// Physical address of the used ring.
    #[inline]
    pub fn used_ring_phys(&self) -> u64 {
        self.used_phys
    }

    /// Allocate a descriptor from the free list.
    ///
    /// Returns `None` if no descriptors are available.
    pub fn alloc_desc(&self) -> Option<u16> {
        // R44-8 LOCK ORDER FIX: Lock alloc_bitmap first, then free_list
        // This matches the order in free_desc to prevent deadlock
        let mut alloc = self.alloc_bitmap.lock();
        let mut free = self.free_list.lock();

        let idx = free.pop()?;
        // R44-8 FIX: Mark descriptor as allocated
        alloc[idx as usize] = true;
        Some(idx)
    }

    /// Free a descriptor back to the free list.
    ///
    /// # R43-3 + R44-8 FIX: Added bounds check, allocation tracking, and double-free detection
    /// - Validates index is within queue bounds
    /// - Checks descriptor was actually allocated before freeing
    /// - Ignores duplicate free attempts to prevent descriptor aliasing
    pub fn free_desc(&self, idx: u16) {
        // R43-3 FIX: Bounds check
        if idx >= self.size {
            return;
        }

        // R44-8 LOCK ORDER FIX: Lock alloc_bitmap first, then free_list
        let mut alloc = self.alloc_bitmap.lock();
        let mut free = self.free_list.lock();

        // R44-8 FIX: Check if descriptor was allocated
        // This prevents freeing forged descriptors from malicious device
        if !alloc.get(idx as usize).copied().unwrap_or(false) {
            // Was not allocated - reject (forged free or double-free)
            return;
        }

        // R43-3 FIX: Detect double-free (redundant with above, but extra safety)
        if free.iter().any(|&v| v == idx) {
            return;
        }

        // Mark as deallocated and add to free list
        alloc[idx as usize] = false;
        free.push(idx);
    }

    /// Get the number of available descriptors.
    pub fn available_descs(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Push a descriptor chain to the available ring.
    ///
    /// # Safety
    /// The caller must ensure the descriptor chain is properly set up.
    pub unsafe fn push_avail(&self, head: u16) {
        let avail = &mut *self.avail;
        let idx = read_volatile(&avail.idx);
        let ring_idx = (idx % self.size) as usize;

        // Write to ring
        let ring_ptr = avail.ring.as_mut_ptr();
        write_volatile(ring_ptr.add(ring_idx), head);

        // Memory barrier before updating idx
        wmb();

        // Update index
        write_volatile(&mut avail.idx, idx.wrapping_add(1));
    }

    /// Check if there are used entries to process.
    pub fn has_used(&self) -> bool {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);
            used_idx != last
        }
    }

    /// Pop a used entry from the used ring.
    ///
    /// Returns `None` if no used entries are available.
    ///
    /// # R44-5 FIX: Validates used.idx jump to prevent reading stale ring slots
    /// If device jumps used.idx beyond queue size, we resync to prevent permanent stall.
    pub fn pop_used(&self) -> Option<VringUsedElem> {
        unsafe {
            let used = &*self.used;
            let used_idx = read_volatile(&used.idx);
            let last = self.last_used_idx.load(Ordering::Relaxed);

            // Calculate how many entries are available
            let available = used_idx.wrapping_sub(last);
            if available == 0 {
                return None;
            }

            // R44-5 FIX: Reject implausible jumps in used.idx
            // A malicious device could jump used.idx far ahead to make us read
            // stale ring slots and free unrelated descriptor chains.
            //
            // R48-1/R48-4 FIX: Also reject backward movement (rewind) to prevent
            // stale-slot replay attacks. When used_idx moves backward without a
            // proper wrap, a malicious device could cause us to re-read old slots
            // and double-free descriptors we already processed.
            //
            // Detection logic:
            // - `available > self.size` indicates an abnormal jump
            // - If `used_idx < last` (backward move without wrap), drop silently
            //   and keep last_used_idx unchanged to prevent replay
            // - If forward jump (wrapped or too far ahead), resync to prevent stall
            if available > self.size {
                if used_idx < last {
                    // Backward move: drop entry, do NOT update last_used_idx
                    // This prevents replaying already-processed slots
                    return None;
                }
                // Forward jump: resync to device index to avoid permanent stall
                // but don't process any entries from this abnormal transition
                self.last_used_idx.store(used_idx, Ordering::Relaxed);
                return None;
            }

            rmb();

            let ring_idx = (last % self.size) as usize;
            let ring_ptr = used.ring.as_ptr();
            let elem = read_volatile(ring_ptr.add(ring_idx));

            self.last_used_idx
                .store(last.wrapping_add(1), Ordering::Relaxed);

            // R148-I7 FIX: Validate descriptor ID returned by the device.
            // A malicious or buggy device could provide an out-of-bounds ID,
            // causing callers' desc_mut(elem.id) to access memory beyond the
            // descriptor table. Advance past the invalid entry (no stall)
            // but don't expose it to the caller.
            if elem.id >= self.size as u32 {
                return None;
            }

            Some(elem)
        }
    }

    /// Get mutable reference to a descriptor at the given index.
    ///
    /// # Safety
    /// The caller must ensure the index is valid and the descriptor
    /// is not currently in use by the device.
    pub unsafe fn desc_mut(&self, idx: u16) -> &mut VringDesc {
        // R150-I2 FIX: Catch out-of-bounds descriptor access in debug builds.
        // All current callers use driver-allocated indices, but a future bug
        // would silently produce UB without this assertion.
        debug_assert!(idx < self.size, "desc_mut: idx {} >= size {}", idx, self.size);
        &mut *self.desc.add(idx as usize)
    }

    /// Get a reference to a descriptor at the given index.
    ///
    /// # Safety
    /// The caller must ensure the index is valid.
    pub unsafe fn desc(&self, idx: u16) -> &VringDesc {
        // R150-I2 FIX: Catch out-of-bounds descriptor access in debug builds.
        debug_assert!(idx < self.size, "desc: idx {} >= size {}", idx, self.size);
        &*self.desc.add(idx as usize)
    }
}
