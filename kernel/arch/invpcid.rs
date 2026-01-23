//! INVPCID Instruction Support for x86_64
//!
//! This module re-exports the INVPCID functions from the `tlb_ops` crate
//! for backwards compatibility with existing code that uses `arch::invpcid`.
//!
//! # INVPCID Types
//!
//! | Type | Name | Description |
//! |------|------|-------------|
//! | 0 | Individual-address | Invalidate single (PCID, linear address) |
//! | 1 | Single-context | Invalidate all mappings for one PCID |
//! | 2 | All-context | Invalidate all non-global mappings (all PCIDs) |
//! | 3 | All-context-global | Invalidate all mappings including globals |
//!
//! # Usage
//!
//! ```rust,ignore
//! if invpcid_supported() {
//!     // Invalidate single address for PCID 5
//!     unsafe { invpcid_address(5, 0x1000_0000); }
//!
//!     // Invalidate all non-global entries for PCID 5
//!     unsafe { invpcid_single_context(5); }
//!
//!     // Invalidate all non-global entries for all PCIDs
//!     unsafe { invpcid_all_nonglobal(); }
//! }
//! ```
//!
//! # Security Considerations
//!
//! - INVPCID type 3 flushes global entries - use sparingly
//! - INVPCID with invalid PCID (>4095) causes #GP
//! - Always gate usage on `invpcid_supported()`

#![cfg(target_arch = "x86_64")]

// Re-export all functions from tlb_ops for backwards compatibility
pub use tlb_ops::{
    flush_address, flush_all_nonglobal, flush_pcid, invpcid_address, invpcid_all_global,
    invpcid_all_nonglobal, invpcid_single_context, invpcid_supported,
};
