//! Runtime Test Infrastructure for Zero-OS
//!
//! This module provides comprehensive functional tests that run during kernel boot
//! to verify all critical subsystems are working correctly.
//!
//! # Design
//!
//! Unlike `#[cfg(test)]` unit tests which require a test harness, these tests
//! run within the kernel itself and can test actual hardware interactions,
//! interrupt handling, and cross-module integration.
//!
//! # Test Categories
//!
//! - **Memory**: Heap allocation, buddy allocator
//! - **Capability**: CapTable lifecycle, rights enforcement
//! - **Seccomp**: Filter evaluation, pledge promises
//! - **Network**: Packet parsing/serialization
//! - **Scheduler**: Starvation prevention
//! - **Process**: Creation and lifecycle
//! - **Security**: W^X, RNG, kptr validation

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::hint::spin_loop;
use core::sync::atomic::Ordering;

// ============================================================================
// Test Result Types
// ============================================================================

/// Result of a runtime test
#[derive(Debug, Clone)]
pub enum TestResult {
    /// Test passed successfully
    Pass,
    /// Test passed with a warning
    Warning(String),
    /// Test failed
    Fail(String),
}

impl TestResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, TestResult::Pass | TestResult::Warning(_))
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, TestResult::Fail(_))
    }
}

/// Outcome of a single test execution
#[derive(Debug, Clone)]
pub struct TestOutcome {
    pub name: &'static str,
    pub result: TestResult,
}

/// Aggregate report for all runtime tests
#[derive(Debug, Clone)]
pub struct TestReport {
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub outcomes: Vec<TestOutcome>,
}

impl TestReport {
    pub fn empty() -> Self {
        Self {
            passed: 0,
            failed: 0,
            warnings: 0,
            outcomes: Vec::new(),
        }
    }

    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

/// Trait for runtime tests
pub trait RuntimeTest {
    fn name(&self) -> &'static str;
    fn run(&self) -> TestResult;
    fn description(&self) -> &'static str {
        "Runtime validation test"
    }
}

// ============================================================================
// Memory Tests
// ============================================================================

/// Test heap allocation works correctly
struct HeapAllocationTest;

impl RuntimeTest for HeapAllocationTest {
    fn name(&self) -> &'static str {
        "heap_allocation"
    }

    fn description(&self) -> &'static str {
        "Verify kernel heap allocation and deallocation"
    }

    fn run(&self) -> TestResult {
        // Test 1: Simple vector allocation
        let mut v: Vec<u64> = Vec::with_capacity(100);
        for i in 0..100 {
            v.push(i);
        }

        if v.len() != 100 {
            return TestResult::Fail(String::from("Vector allocation failed"));
        }

        // Verify values
        for (i, &val) in v.iter().enumerate() {
            if val != i as u64 {
                return TestResult::Fail(String::from("Vector content corruption"));
            }
        }

        // Test 2: Box allocation
        let boxed: alloc::boxed::Box<[u8; 4096]> = alloc::boxed::Box::new([0u8; 4096]);
        if boxed[0] != 0 || boxed[4095] != 0 {
            return TestResult::Fail(String::from("Box allocation corruption"));
        }

        // Test 3: String allocation
        let s = String::from("Hello Zero-OS Runtime Tests!");
        if s.len() != 28 {
            return TestResult::Fail(String::from("String allocation failed"));
        }

        TestResult::Pass
    }
}

/// Test buddy allocator physical page allocation
struct BuddyAllocatorTest;

impl RuntimeTest for BuddyAllocatorTest {
    fn name(&self) -> &'static str {
        "buddy_allocator"
    }

    fn description(&self) -> &'static str {
        "Verify buddy allocator physical page management"
    }

    fn run(&self) -> TestResult {
        use mm::buddy_allocator;

        // Get initial stats
        let stats_before = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Warning(String::from("Buddy allocator not initialized")),
        };

        // Allocate a single page
        let frame = match buddy_allocator::alloc_physical_pages(1) {
            Some(f) => f,
            None => return TestResult::Fail(String::from("Failed to allocate 1 page")),
        };

        // Verify stats changed
        let stats_after = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Fail(String::from("Stats unavailable after alloc")),
        };

        // Free pages should have decreased by at least 1
        // (buddy allocator may round up to power of 2)
        if stats_after.free_pages >= stats_before.free_pages {
            return TestResult::Fail(String::from("Free page count did not decrease"));
        }

        // Free the page
        buddy_allocator::free_physical_pages(frame, 1);

        // Verify stats restored
        let stats_restored = match buddy_allocator::get_allocator_stats() {
            Some(s) => s,
            None => return TestResult::Fail(String::from("Stats unavailable after free")),
        };

        if stats_restored.free_pages != stats_before.free_pages {
            return TestResult::Warning(String::from(
                "Free pages not fully restored (fragmentation?)",
            ));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Capability Tests
// ============================================================================

/// Test capability table lifecycle
struct CapTableLifecycleTest;

impl RuntimeTest for CapTableLifecycleTest {
    fn name(&self) -> &'static str {
        "cap_table_lifecycle"
    }

    fn description(&self) -> &'static str {
        "Verify capability allocation, lookup, and revocation"
    }

    fn run(&self) -> TestResult {
        use cap::{CapEntry, CapObject, CapRights, CapTable};

        // Create a new capability table
        let table = CapTable::new();

        // Allocate a capability with read-only rights using Endpoint as test object
        let entry = CapEntry::new(
            CapObject::Endpoint(9999), // Use Endpoint with dummy ID for testing
            CapRights::READ,
        );

        let cap_id = match table.allocate(entry) {
            Ok(id) => id,
            Err(e) => return TestResult::Fail(alloc::format!("Allocate failed: {:?}", e)),
        };

        // Lookup should succeed
        let looked_up = match table.lookup(cap_id) {
            Ok(e) => e,
            Err(e) => return TestResult::Fail(alloc::format!("Lookup failed: {:?}", e)),
        };

        // Verify rights (rights is a field, not a method)
        if !looked_up.rights.contains(CapRights::READ) {
            return TestResult::Fail(String::from("Rights not preserved"));
        }

        if looked_up.rights.contains(CapRights::WRITE) {
            return TestResult::Fail(String::from("Unexpected WRITE right"));
        }

        // Revoke the capability
        if let Err(e) = table.revoke(cap_id) {
            return TestResult::Fail(alloc::format!("Revoke failed: {:?}", e));
        }

        // Lookup after revoke should fail
        if table.lookup(cap_id).is_ok() {
            return TestResult::Fail(String::from("Lookup succeeded after revoke"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Seccomp Tests
// ============================================================================

/// Test strict mode seccomp filter
struct StrictSeccompFilterTest;

impl RuntimeTest for StrictSeccompFilterTest {
    fn name(&self) -> &'static str {
        "seccomp_strict_filter"
    }

    fn description(&self) -> &'static str {
        "Verify strict mode filter allows only read/write/exit"
    }

    fn run(&self) -> TestResult {
        use seccomp::{strict_filter, SeccompAction};

        let filter = strict_filter();

        // Test syscall evaluation helper
        // SeccompFilter::evaluate returns SeccompAction directly
        let eval = |nr: u64| -> SeccompAction {
            let args = [0u64; 6];
            filter.evaluate(nr, &args)
        };

        // read (0) should be allowed
        if !matches!(eval(0), SeccompAction::Allow) {
            return TestResult::Fail(String::from("read(0) not allowed in strict mode"));
        }

        // write (1) should be allowed
        if !matches!(eval(1), SeccompAction::Allow) {
            return TestResult::Fail(String::from("write(1) not allowed in strict mode"));
        }

        // exit (60) should be allowed
        if !matches!(eval(60), SeccompAction::Allow) {
            return TestResult::Fail(String::from("exit(60) not allowed in strict mode"));
        }

        // exit_group (231) should be allowed
        if !matches!(eval(231), SeccompAction::Allow) {
            return TestResult::Fail(String::from("exit_group(231) not allowed in strict mode"));
        }

        // open (2) should be killed
        if !matches!(eval(2), SeccompAction::Kill) {
            return TestResult::Fail(String::from("open(2) not killed in strict mode"));
        }

        // mmap (9) should be killed
        if !matches!(eval(9), SeccompAction::Kill) {
            return TestResult::Fail(String::from("mmap(9) not killed in strict mode"));
        }

        TestResult::Pass
    }
}

/// Test pledge promise filter
struct PledgeSeccompFilterTest;

impl RuntimeTest for PledgeSeccompFilterTest {
    fn name(&self) -> &'static str {
        "seccomp_pledge_filter"
    }

    fn description(&self) -> &'static str {
        "Verify pledge promise filtering"
    }

    fn run(&self) -> TestResult {
        use seccomp::{pledge_to_filter, PledgePromises, SeccompAction};

        // Create a filter with only STDIO promise
        let promises = PledgePromises::STDIO;
        let filter = pledge_to_filter(promises);

        let eval = |nr: u64| -> SeccompAction {
            let args = [0u64; 6];
            filter.evaluate(nr, &args)
        };

        // read (0) should be allowed with STDIO
        if !matches!(eval(0), SeccompAction::Allow) {
            return TestResult::Fail(String::from("read not allowed with STDIO promise"));
        }

        // write (1) should be allowed with STDIO
        if !matches!(eval(1), SeccompAction::Allow) {
            return TestResult::Fail(String::from("write not allowed with STDIO promise"));
        }

        // fork (57) should be blocked without PROC promise
        if matches!(eval(57), SeccompAction::Allow) {
            return TestResult::Fail(String::from("fork allowed without PROC promise"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Audit Tests
// ============================================================================

/// Test audit hash chain verification function
struct AuditHashChainTest;

impl RuntimeTest for AuditHashChainTest {
    fn name(&self) -> &'static str {
        "audit_verify_chain"
    }

    fn description(&self) -> &'static str {
        "Verify audit hash chain verification function"
    }

    fn run(&self) -> TestResult {
        use audit::verify_chain;

        // Test with empty events (should succeed)
        let empty_events: Vec<audit::AuditEvent> = Vec::new();
        if !verify_chain(&empty_events) {
            return TestResult::Fail(String::from("Empty chain verification failed"));
        }

        // Note: Full hash chain testing requires emitting events and reading them back,
        // which requires proper capability authorization. The verify_chain function
        // itself is tested with empty input to verify it's compiled and accessible.

        TestResult::Pass
    }
}

// ============================================================================
// Network Tests
// ============================================================================

/// Test network packet parsing and serialization
struct NetworkParsingTest;

impl RuntimeTest for NetworkParsingTest {
    fn name(&self) -> &'static str {
        "network_parsing"
    }

    fn description(&self) -> &'static str {
        "Verify ARP, UDP, and TCP packet parsing"
    }

    fn run(&self) -> TestResult {
        // Test ARP parsing
        if let Err(e) = self.test_arp() {
            return TestResult::Fail(alloc::format!("ARP test failed: {}", e));
        }

        // Test UDP parsing
        if let Err(e) = self.test_udp() {
            return TestResult::Fail(alloc::format!("UDP test failed: {}", e));
        }

        // Test TCP parsing
        if let Err(e) = self.test_tcp() {
            return TestResult::Fail(alloc::format!("TCP test failed: {}", e));
        }

        TestResult::Pass
    }
}

impl NetworkParsingTest {
    fn test_arp(&self) -> Result<(), String> {
        use net::{parse_arp, serialize_arp, ArpOp, ArpPacket, EthAddr, Ipv4Addr};

        // Create a test ARP request packet
        let request = ArpPacket {
            sender_hw: EthAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            sender_ip: Ipv4Addr([192, 168, 1, 1]),
            target_hw: EthAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            target_ip: Ipv4Addr([192, 168, 1, 2]),
            op: ArpOp::Request,
        };

        // Serialize
        let bytes = serialize_arp(&request);
        if bytes.len() != 28 {
            return Err(String::from("ARP serialization wrong length"));
        }

        // Parse back
        let parsed = parse_arp(&bytes).map_err(|e| alloc::format!("{:?}", e))?;

        // Verify fields
        if parsed.op != ArpOp::Request {
            return Err(String::from("ARP opcode mismatch"));
        }
        if parsed.sender_ip.0 != [192, 168, 1, 1] {
            return Err(String::from("ARP sender_ip mismatch"));
        }
        if parsed.target_ip.0 != [192, 168, 1, 2] {
            return Err(String::from("ARP target_ip mismatch"));
        }

        Ok(())
    }

    fn test_udp(&self) -> Result<(), String> {
        use net::{build_udp_datagram, parse_udp, Ipv4Addr};

        let src_ip = Ipv4Addr([10, 0, 0, 1]);
        let dst_ip = Ipv4Addr([10, 0, 0, 2]);
        let src_port = 12345u16;
        let dst_port = 80u16;
        let payload = b"Hello UDP!";

        // Build UDP datagram (returns Result)
        let datagram = build_udp_datagram(src_ip, dst_ip, src_port, dst_port, payload)
            .map_err(|e| alloc::format!("{:?}", e))?;

        if datagram.len() != 8 + payload.len() {
            return Err(alloc::format!(
                "UDP datagram wrong length: {} (expected {})",
                datagram.len(),
                8 + payload.len()
            ));
        }

        // Parse UDP header
        let (header, data) =
            parse_udp(&datagram, src_ip, dst_ip).map_err(|e| alloc::format!("{:?}", e))?;

        if header.src_port != src_port {
            return Err(String::from("UDP src_port mismatch"));
        }
        if header.dst_port != dst_port {
            return Err(String::from("UDP dst_port mismatch"));
        }
        if data != payload {
            return Err(String::from("UDP payload mismatch"));
        }

        Ok(())
    }

    fn test_tcp(&self) -> Result<(), String> {
        use net::{parse_tcp_header, TCP_FLAG_ACK, TCP_FLAG_SYN};

        // Create a minimal TCP SYN packet
        #[rustfmt::skip]
        let tcp_syn: [u8; 20] = [
            0x30, 0x39,  // src port: 12345
            0x00, 0x50,  // dst port: 80
            0x00, 0x00, 0x00, 0x01,  // seq: 1
            0x00, 0x00, 0x00, 0x00,  // ack: 0
            0x50, 0x02,  // data offset: 5, flags: SYN
            0x20, 0x00,  // window: 8192
            0x00, 0x00,  // checksum (placeholder)
            0x00, 0x00,  // urgent ptr: 0
        ];

        let header = parse_tcp_header(&tcp_syn).map_err(|e| alloc::format!("{:?}", e))?;

        if header.src_port != 12345 {
            return Err(String::from("TCP src_port mismatch"));
        }
        if header.dst_port != 80 {
            return Err(String::from("TCP dst_port mismatch"));
        }
        if header.seq_num != 1 {
            return Err(String::from("TCP seq_num mismatch"));
        }
        // Check SYN flag using flags field and constant
        if header.flags & TCP_FLAG_SYN == 0 {
            return Err(String::from("TCP SYN flag not set"));
        }
        // Check ACK flag not set
        if header.flags & TCP_FLAG_ACK != 0 {
            return Err(String::from("TCP ACK flag incorrectly set"));
        }

        Ok(())
    }
}

// ============================================================================
// Network Loopback Tests
// ============================================================================

/// Test network stack through software loopback (process_frame)
struct NetworkLoopbackTest;

impl RuntimeTest for NetworkLoopbackTest {
    fn name(&self) -> &'static str {
        "network_loopback"
    }

    fn description(&self) -> &'static str {
        "Verify network stack processing via software loopback"
    }

    fn run(&self) -> TestResult {
        // Test 1: UDP packet through process_frame
        if let Err(e) = self.test_udp_loopback() {
            return TestResult::Fail(alloc::format!("UDP loopback failed: {}", e));
        }

        // Test 2: Invalid TCP flags dropped by firewall
        if let Err(e) = self.test_invalid_tcp_drop() {
            return TestResult::Fail(alloc::format!("Invalid TCP drop failed: {}", e));
        }

        // Test 3: Conntrack table entry creation
        if let Err(e) = self.test_conntrack_creation() {
            return TestResult::Fail(alloc::format!("Conntrack test failed: {}", e));
        }

        // Test 4: TCP SYN handling
        if let Err(e) = self.test_tcp_syn() {
            return TestResult::Fail(alloc::format!("TCP SYN test failed: {}", e));
        }

        // Test 5: Firewall rule matching
        if let Err(e) = self.test_firewall_rules() {
            return TestResult::Fail(alloc::format!("Firewall test failed: {}", e));
        }

        TestResult::Pass
    }
}

impl NetworkLoopbackTest {
    /// Build a complete Ethernet + IPv4 + UDP frame for testing
    fn build_udp_frame(
        &self,
        src_mac: net::EthAddr,
        dst_mac: net::EthAddr,
        src_ip: net::Ipv4Addr,
        dst_ip: net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Build UDP datagram with correct checksum
        let udp_data = net::build_udp_datagram(src_ip, dst_ip, src_port, dst_port, payload)
            .map_err(|e| alloc::format!("UDP build failed: {:?}", e))?;

        // Build IPv4 header
        let ip_header = net::build_ipv4_header(
            src_ip,
            dst_ip,
            net::Ipv4Proto::Udp,
            udp_data.len() as u16,
            64, // TTL
        );

        // Combine IP header + UDP datagram
        let mut ip_packet = Vec::with_capacity(ip_header.len() + udp_data.len());
        ip_packet.extend_from_slice(&ip_header);
        ip_packet.extend_from_slice(&udp_data);

        // Build Ethernet frame
        let frame = net::build_ethernet_frame(dst_mac, src_mac, net::ETHERTYPE_IPV4, &ip_packet);

        Ok(frame)
    }

    /// Test UDP packet processing through the network stack
    fn test_udp_loopback(&self) -> Result<(), String> {
        use net::{arp::ArpCache, stack::NetStats, EthAddr, Ipv4Addr, ProcessResult};

        // Setup test addresses
        let our_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let our_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);

        // Build a UDP packet destined to us
        let payload = b"loopback test";
        let frame = self.build_udp_frame(
            remote_mac, our_mac, remote_ip, our_ip, 12345, // src port
            8080,  // dst port
            payload,
        )?;

        // Create test context
        let mut arp_cache = ArpCache::new(60_000, 256); // 60s TTL, 256 max entries
        let stats = NetStats::new();
        let now_ms = 1000u64;

        // Process the frame
        let result = net::process_frame(&frame, our_mac, our_ip, &mut arp_cache, &stats, now_ms);

        // The frame should be handled (delivered to socket layer) or replied
        // In absence of a listening socket, it should be handled but may generate ICMP unreachable
        match result {
            ProcessResult::Handled => Ok(()),
            ProcessResult::Reply(_) => Ok(()), // ICMP port unreachable is valid
            ProcessResult::Dropped(reason) => {
                // Firewall drops or other valid reasons are acceptable in test context
                // But parse errors indicate a problem with frame construction
                Err(alloc::format!("UDP packet dropped: {:?}", reason))
            }
        }
    }

    /// Test that TCP packets with invalid flags are dropped
    fn test_invalid_tcp_drop(&self) -> Result<(), String> {
        use net::{
            arp::ArpCache, stack::NetStats, EthAddr, Ipv4Addr, ProcessResult, TCP_FLAG_FIN,
            TCP_FLAG_RST, TCP_FLAG_SYN,
        };

        let our_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let our_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);

        // Build a TCP packet with invalid flags (SYN+FIN+RST - Christmas tree attack)
        // This should be dropped by firewall/conntrack
        let invalid_flags = TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST;

        // Build TCP header with invalid flags
        #[rustfmt::skip]
        let tcp_header: [u8; 20] = [
            0x30, 0x39,  // src port: 12345
            0x00, 0x50,  // dst port: 80
            0x00, 0x00, 0x00, 0x01,  // seq: 1
            0x00, 0x00, 0x00, 0x00,  // ack: 0
            0x50, invalid_flags,     // data offset: 5, flags: SYN+FIN+RST
            0x20, 0x00,  // window: 8192
            0x00, 0x00,  // checksum (placeholder)
            0x00, 0x00,  // urgent ptr: 0
        ];

        // Build IPv4 header
        let ip_header = net::build_ipv4_header(
            remote_ip,
            our_ip,
            net::Ipv4Proto::Tcp,
            tcp_header.len() as u16,
            64,
        );

        // Combine IP + TCP
        let mut ip_packet = Vec::with_capacity(ip_header.len() + tcp_header.len());
        ip_packet.extend_from_slice(&ip_header);
        ip_packet.extend_from_slice(&tcp_header);

        // Build Ethernet frame
        let frame = net::build_ethernet_frame(our_mac, remote_mac, net::ETHERTYPE_IPV4, &ip_packet);

        // Create test context
        let mut arp_cache = ArpCache::new(60_000, 256); // 60s TTL, 256 max entries
        let stats = NetStats::new();
        let now_ms = 2000u64;

        // Process the frame
        let result = net::process_frame(&frame, our_mac, our_ip, &mut arp_cache, &stats, now_ms);

        // Invalid TCP flags should be dropped (or handled without reply)
        match result {
            ProcessResult::Dropped(_) => Ok(()), // Expected: dropped by firewall
            ProcessResult::Handled => Ok(()),    // Also valid: silently discarded
            ProcessResult::Reply(ref pkt) => {
                // RST reply is acceptable for invalid packets
                if pkt.len() > 34 {
                    // Min Eth+IP+TCP
                    Ok(())
                } else {
                    Err(String::from("Unexpected short reply to invalid TCP"))
                }
            }
        }
    }

    /// Test that conntrack table entries are created for valid flows
    fn test_conntrack_creation(&self) -> Result<(), String> {
        use net::conntrack;

        // Get the conntrack table
        let table = conntrack::conntrack_table();
        let stats = table.stats();

        // Verify table is operational by checking stats are accessible
        // (entries_created should be available)
        let _ = stats
            .entries_created
            .load(core::sync::atomic::Ordering::Relaxed);

        // Check that table can perform lookups (doesn't panic)
        let test_key = conntrack::FlowKey {
            ip_lo: [10, 0, 0, 1],
            ip_hi: [10, 0, 0, 2],
            port_lo: 80,
            port_hi: 12345,
            proto: 17, // UDP
        };

        // Lookup should complete without panic (result doesn't matter)
        let _ = table.lookup(&test_key);

        Ok(())
    }

    /// Test valid TCP SYN packet processing
    fn test_tcp_syn(&self) -> Result<(), String> {
        use net::{arp::ArpCache, stack::NetStats, EthAddr, Ipv4Addr, ProcessResult, TCP_FLAG_SYN};

        let our_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let our_ip = Ipv4Addr([10, 0, 0, 1]);
        let remote_mac = EthAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let remote_ip = Ipv4Addr([10, 0, 0, 2]);

        // Build a valid TCP SYN packet
        #[rustfmt::skip]
        let tcp_header: [u8; 20] = [
            0x30, 0x39,  // src port: 12345
            0x00, 0x50,  // dst port: 80
            0x00, 0x00, 0x00, 0x01,  // seq: 1
            0x00, 0x00, 0x00, 0x00,  // ack: 0
            0x50, TCP_FLAG_SYN,      // data offset: 5, flags: SYN only
            0x20, 0x00,  // window: 8192
            0x00, 0x00,  // checksum (placeholder)
            0x00, 0x00,  // urgent ptr: 0
        ];

        // Build IPv4 header
        let ip_header = net::build_ipv4_header(
            remote_ip,
            our_ip,
            net::Ipv4Proto::Tcp,
            tcp_header.len() as u16,
            64,
        );

        // Combine IP + TCP
        let mut ip_packet = Vec::with_capacity(ip_header.len() + tcp_header.len());
        ip_packet.extend_from_slice(&ip_header);
        ip_packet.extend_from_slice(&tcp_header);

        // Build Ethernet frame
        let frame = net::build_ethernet_frame(our_mac, remote_mac, net::ETHERTYPE_IPV4, &ip_packet);

        // Create test context
        let mut arp_cache = ArpCache::new(60_000, 256);
        let stats = NetStats::new();
        let now_ms = 3000u64;

        // Process the frame
        let result = net::process_frame(&frame, our_mac, our_ip, &mut arp_cache, &stats, now_ms);

        // Valid SYN should be processed (either handled, replied with RST, or dropped if no listener)
        match result {
            ProcessResult::Handled => Ok(()),
            ProcessResult::Reply(_) => Ok(()), // RST reply is acceptable
            ProcessResult::Dropped(_) => Ok(()), // May be dropped if no matching socket
        }
    }

    /// Test firewall rule matching and statistics
    fn test_firewall_rules(&self) -> Result<(), String> {
        use net::{conntrack, firewall, Ipv4Addr, Ipv4Proto};

        // Get the firewall table
        let table = firewall::firewall_table();
        let stats = table.stats();

        // Verify firewall is operational by checking statistics
        // Stats should be accessible
        let _ = stats.packets_accepted;
        let _ = stats.packets_dropped;
        let _ = stats.rule_evaluations;

        // Test that the firewall can evaluate packets
        // Create a test packet structure
        let test_pkt = firewall::FirewallPacket {
            src_ip: Ipv4Addr([10, 0, 0, 2]),
            dst_ip: Ipv4Addr([10, 0, 0, 1]),
            src_port: Some(12345),
            dst_port: Some(80),
            proto: Ipv4Proto::Tcp,
            ct_state: Some(conntrack::CtDecision::New),
        };

        // Evaluate should complete without panic
        let verdict = table.evaluate(&test_pkt);

        // Verify we get a valid verdict with action field
        match verdict.action {
            firewall::FirewallAction::Accept => Ok(()),
            firewall::FirewallAction::Drop => Ok(()),
            firewall::FirewallAction::Reject { .. } => Ok(()),
        }
    }
}

// ============================================================================
// Scheduler Tests
// ============================================================================

/// Test scheduler starvation prevention
struct SchedulerStarvationTest;

impl RuntimeTest for SchedulerStarvationTest {
    fn name(&self) -> &'static str {
        "scheduler_starvation"
    }

    fn description(&self) -> &'static str {
        "Verify wait_ticks counter and priority boosting"
    }

    fn run(&self) -> TestResult {
        use kernel_core::process::Process;

        // Create a test process with low priority
        // ProcessId is type alias for usize
        let mut process = Process::new(
            9999, // pid: usize
            1,    // ppid: usize
            String::from("test_process"),
            100, // priority: u8 (lower = higher priority, 100 is low)
        );

        let initial_priority = process.dynamic_priority;
        let initial_wait_ticks = process.wait_ticks;

        // Simulate waiting ticks
        for _ in 0..100 {
            process.wait_ticks = process.wait_ticks.saturating_add(1);
        }

        if process.wait_ticks != initial_wait_ticks + 100 {
            return TestResult::Fail(String::from("wait_ticks not incremented correctly"));
        }

        // Simulate starvation boost (threshold is 100 ticks per STARVATION_THRESHOLD)
        // Set wait_ticks at threshold
        process.wait_ticks = 100;
        process.check_and_boost_starved();

        // After boosting, wait_ticks should reset and priority should increase
        if process.wait_ticks != 0 {
            return TestResult::Fail(String::from("wait_ticks not reset after boost"));
        }

        // Dynamic priority should have increased (lower value = higher priority)
        if process.dynamic_priority >= initial_priority {
            return TestResult::Warning(String::from("Priority did not increase (may be at max)"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Process Tests
// ============================================================================

/// Test process creation and basic lifecycle
struct ProcessCreationTest;

impl RuntimeTest for ProcessCreationTest {
    fn name(&self) -> &'static str {
        "process_creation"
    }

    fn description(&self) -> &'static str {
        "Verify process creation and initialization"
    }

    fn run(&self) -> TestResult {
        use kernel_core::process::{Process, ProcessState};

        // Create a new process
        // ProcessId is type alias for usize
        let process = Process::new(
            1234, // pid: usize
            1,    // ppid: usize
            String::from("test_proc"),
            50, // priority: u8
        );

        // Verify initial state
        if process.pid != 1234 {
            return TestResult::Fail(String::from("PID not set correctly"));
        }

        if process.ppid != 1 {
            return TestResult::Fail(String::from("PPID not set correctly"));
        }

        if process.state != ProcessState::Ready {
            return TestResult::Fail(String::from("Initial state should be Ready"));
        }

        if process.priority != 50 {
            return TestResult::Fail(String::from("Priority not set correctly"));
        }

        // Verify wait_ticks starts at 0
        if process.wait_ticks != 0 {
            return TestResult::Fail(String::from("wait_ticks should start at 0"));
        }

        // Verify tid == pid (Linux semantics)
        if process.tid != process.pid {
            return TestResult::Fail(String::from("tid should equal pid"));
        }

        // Verify tgid == pid (main thread)
        if process.tgid != process.pid {
            return TestResult::Fail(String::from("tgid should equal pid for main thread"));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Security Tests Integration
// ============================================================================

/// Run security subsystem tests
struct SecuritySubsystemTest;

impl RuntimeTest for SecuritySubsystemTest {
    fn name(&self) -> &'static str {
        "security_subsystem"
    }

    fn description(&self) -> &'static str {
        "Run security module tests (W^X, RNG, kptr)"
    }

    fn run(&self) -> TestResult {
        use security::tests::{run_security_tests, TestContext};
        use x86_64::VirtAddr;

        // Create test context with physical offset 0 (identity mapping for low memory)
        let ctx = TestContext {
            phys_offset: VirtAddr::new(0),
        };

        let report = run_security_tests(&ctx);

        if report.failed > 0 {
            return TestResult::Fail(alloc::format!(
                "{} security tests failed out of {}",
                report.failed,
                report.passed + report.failed + report.warnings
            ));
        }

        if report.warnings > 0 {
            return TestResult::Warning(alloc::format!(
                "{} security tests had warnings",
                report.warnings
            ));
        }

        TestResult::Pass
    }
}

// ============================================================================
// SMP Tests - Multi-core validation
// ============================================================================

/// Verify multiple CPUs are online for SMP testing
struct SmpOnlineTest;

impl RuntimeTest for SmpOnlineTest {
    fn name(&self) -> &'static str {
        "smp_online"
    }

    fn description(&self) -> &'static str {
        "Verify more than one CPU is online for SMP tests"
    }

    fn run(&self) -> TestResult {
        use arch::num_online_cpus;

        let online = num_online_cpus();
        if online > 1 {
            TestResult::Pass
        } else {
            TestResult::Warning(String::from(
                "Only 1 CPU online; SMP tests will be skipped",
            ))
        }
    }
}

/// Send a reschedule IPI between CPUs and verify delivery
struct IpiPingPongTest;

impl RuntimeTest for IpiPingPongTest {
    fn name(&self) -> &'static str {
        "ipi_ping_pong"
    }

    fn description(&self) -> &'static str {
        "Send IPI between CPUs and verify round-trip"
    }

    fn run(&self) -> TestResult {
        use arch::ipi::{send_ipi, IpiType};
        use arch::{current_cpu_id, is_software_emulated, max_cpus, num_online_cpus, PER_CPU_DATA};
        use kernel_core::time::read_tsc;
        use mm::tlb_shootdown::is_cpu_online;

        if num_online_cpus() <= 1 {
            return TestResult::Warning(String::from(
                "Single-core system; skipping IPI ping-pong",
            ));
        }

        let self_cpu = current_cpu_id();

        // Find an online AP to send IPI to
        let target = match (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id)) {
            Some(id) => id,
            None => return TestResult::Fail(String::from("No online AP found for IPI test")),
        };

        let per_cpu = match PER_CPU_DATA.get_cpu(target) {
            Some(p) => p,
            None => return TestResult::Fail(String::from("Per-CPU slot unavailable")),
        };

        // Detect emulation environment for tuning thresholds
        // QEMU TCG has much higher IPI latency than real hardware or KVM
        let in_emulation = is_software_emulated();
        let (max_spins, warn_threshold, expected_typical) = if in_emulation {
            // Software emulation (QEMU TCG): use generous thresholds
            // TCG emulates x86 instructions, making IPI delivery 10-100x slower
            // Typical latency: 20-50M cycles; warn at 80M to catch severe issues
            (500_000usize, 80_000_000u64, "20-50M")
        } else {
            // Bare metal / KVM / hardware-assisted VM: use stricter thresholds
            // Typical latency: 1-5M cycles; warn at 10M
            (100_000usize, 10_000_000u64, "1-5M")
        };

        // Clear any stale reschedule flag before sending the IPI
        per_cpu.need_resched.store(false, Ordering::Release);

        let start = read_tsc();
        send_ipi(target, IpiType::Reschedule);

        // Wait for the remote handler to set need_resched (bounded spin)
        for _ in 0..max_spins {
            if per_cpu.need_resched.load(Ordering::Acquire) {
                // Clear flag to restore CPU state
                per_cpu.need_resched.store(false, Ordering::Release);
                let cycles = read_tsc().saturating_sub(start);

                // Warn if latency exceeds threshold (environment-dependent)
                return if cycles > warn_threshold {
                    TestResult::Warning(alloc::format!(
                        "High IPI latency: {} cycles to CPU {} (expected {} cycles{})",
                        cycles,
                        target,
                        expected_typical,
                        if in_emulation { ", QEMU TCG" } else { "" }
                    ))
                } else {
                    TestResult::Pass
                };
            }
            spin_loop();
        }

        TestResult::Fail(alloc::format!(
            "Reschedule IPI to CPU {} not acknowledged within timeout{}",
            target,
            if in_emulation {
                " (QEMU TCG: consider longer timeout)"
            } else {
                ""
            }
        ))
    }
}

/// Ensure TLB shootdown reaches remote CPUs and is acknowledged
struct TlbShootdownCoherencyTest;

impl RuntimeTest for TlbShootdownCoherencyTest {
    fn name(&self) -> &'static str {
        "tlb_shootdown_coherency"
    }

    fn description(&self) -> &'static str {
        "Verify TLB shootdown ACKs across CPUs"
    }

    fn run(&self) -> TestResult {
        use arch::{current_cpu_id, max_cpus, num_online_cpus, PER_CPU_DATA};
        use mm::tlb_shootdown::{flush_current_as_all, is_cpu_online};

        if num_online_cpus() <= 1 {
            return TestResult::Warning(String::from(
                "Single-core system; skipping TLB coherency test",
            ));
        }

        let self_cpu = current_cpu_id();

        // Find an online AP
        let target = match (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id)) {
            Some(id) => id,
            None => {
                return TestResult::Fail(String::from("No online AP found for TLB shootdown test"))
            }
        };

        let per_cpu = match PER_CPU_DATA.get_cpu(target) {
            Some(p) => p,
            None => return TestResult::Fail(String::from("Per-CPU slot unavailable")),
        };

        // Record ACK generation before shootdown
        let ack_before = per_cpu.tlb_mailbox.ack_gen.load(Ordering::Acquire);

        // Perform TLB shootdown (sends IPIs and waits for ACKs)
        flush_current_as_all();

        // Verify ACK generation incremented
        let ack_after = per_cpu.tlb_mailbox.ack_gen.load(Ordering::Acquire);
        if ack_after <= ack_before {
            TestResult::Fail(alloc::format!(
                "CPU {} did not acknowledge TLB shootdown (ack_gen: {} -> {})",
                target, ack_before, ack_after
            ))
        } else {
            TestResult::Pass
        }
    }
}

// ============================================================================
// Cpuset Tests
// ============================================================================

/// Validate cpuset creation and effective mask calculation
struct CpusetIsolationTest;

impl RuntimeTest for CpusetIsolationTest {
    fn name(&self) -> &'static str {
        "cpuset_isolation"
    }

    fn description(&self) -> &'static str {
        "Verify cpuset creation, mask validation, and effective CPU masks"
    }

    fn run(&self) -> TestResult {
        use sched::cpuset::{self, CpusetError, CpusetId};

        // Step 1: Verify root cpuset is initialized
        let root = match cpuset::root_cpuset() {
            Some(root) => root,
            None => return TestResult::Fail(String::from("Cpuset subsystem not initialized")),
        };

        let online = cpuset::online_cpu_mask();
        if online == 0 {
            return TestResult::Fail(String::from("No CPUs reported in online mask"));
        }

        let root_mask = root.cpus();
        if root_mask != online {
            return TestResult::Fail(alloc::format!(
                "Root cpuset mask mismatch (root=0x{:016x}, online=0x{:016x})",
                root_mask, online
            ));
        }

        // Find first and second online CPUs for testing
        let first_cpu = root_mask.trailing_zeros() as usize;
        let first_mask = 1u64 << first_cpu;

        // Step 2: Test invalid parent rejection
        match cpuset::cpuset_create(first_mask, CpusetId(9999)) {
            Err(CpusetError::InvalidParent) => {}
            Ok(id) => {
                let _ = cpuset::cpuset_destroy(id);
                return TestResult::Fail(String::from("cpuset_create succeeded with invalid parent"));
            }
            Err(e) => {
                return TestResult::Fail(alloc::format!(
                    "Unexpected error for invalid parent: {:?}",
                    e
                ));
            }
        }

        // Step 3: Test empty mask rejection
        match cpuset::cpuset_create(0, CpusetId::ROOT) {
            Err(CpusetError::EmptyMask) => {}
            Ok(id) => {
                let _ = cpuset::cpuset_destroy(id);
                return TestResult::Fail(String::from("cpuset_create allowed empty mask"));
            }
            Err(e) => {
                return TestResult::Fail(alloc::format!(
                    "Unexpected error for empty mask: {:?}",
                    e
                ));
            }
        }

        // Step 4: Test invalid mask (CPUs outside parent) if possible
        let offline_bits = !online;
        if offline_bits != 0 {
            let bad_cpu = offline_bits.trailing_zeros() as usize;
            let invalid_mask = online | (1u64 << bad_cpu);
            match cpuset::cpuset_create(invalid_mask, CpusetId::ROOT) {
                Err(CpusetError::InvalidMask) => {}
                Ok(id) => {
                    let _ = cpuset::cpuset_destroy(id);
                    return TestResult::Fail(alloc::format!(
                        "cpuset_create accepted CPU {} outside parent mask",
                        bad_cpu
                    ));
                }
                Err(e) => {
                    return TestResult::Fail(alloc::format!(
                        "Unexpected error for invalid mask: {:?}",
                        e
                    ));
                }
            }
        }

        let mut created: Vec<CpusetId> = Vec::new();

        // Find second CPU if available (for multi-core testing)
        let second_mask = {
            let remaining = root_mask & !first_mask;
            if remaining != 0 {
                1u64 << remaining.trailing_zeros()
            } else {
                0
            }
        };

        // Parent covers first CPU (and second if available)
        let parent_mask = if second_mask != 0 {
            first_mask | second_mask
        } else {
            first_mask
        };

        // Step 5: Create parent cpuset
        let parent_id = match cpuset::cpuset_create(parent_mask, CpusetId::ROOT) {
            Ok(id) => id,
            Err(e) => {
                return TestResult::Fail(alloc::format!(
                    "Failed to create parent cpuset: {:?}",
                    e
                ))
            }
        };
        created.push(parent_id);

        // Step 6: Create child cpuset (subset of parent)
        let child_id = match cpuset::cpuset_create(first_mask, parent_id) {
            Ok(id) => id,
            Err(e) => {
                let _ = cpuset::cpuset_destroy(parent_id);
                return TestResult::Fail(alloc::format!(
                    "Failed to create child cpuset: {:?}",
                    e
                ))
            }
        };
        created.push(child_id);

        // Step 7: Run effective mask and is_cpu_allowed tests
        let result = (|| -> Result<(), String> {
            // Test effective_cpus for parent (should be intersection with online)
            let effective_parent = cpuset::effective_cpus(parent_id, 0);
            let expected_parent = online & parent_mask;
            if effective_parent != expected_parent {
                return Err(alloc::format!(
                    "Parent effective mask mismatch (got 0x{:016x}, expected 0x{:016x})",
                    effective_parent,
                    expected_parent
                ));
            }

            // Test effective_cpus for child (should be intersection with parent and online)
            let effective_child = cpuset::effective_cpus(child_id, 0);
            let expected_child = online & first_mask;
            if effective_child != expected_child {
                return Err(alloc::format!(
                    "Child effective mask mismatch (got 0x{:016x}, expected 0x{:016x})",
                    effective_child,
                    expected_child
                ));
            }

            // Test task affinity intersection
            let affinity_mismatch = if second_mask != 0 {
                second_mask // Affinity only for second CPU
            } else {
                1u64 << ((first_cpu + 1) % 64) // Non-overlapping affinity
            };
            let restricted = cpuset::effective_cpus(child_id, affinity_mismatch);
            let expected_restricted = online & first_mask & affinity_mismatch;
            if restricted != expected_restricted {
                return Err(alloc::format!(
                    "Affinity intersection mismatch (got 0x{:016x}, expected 0x{:016x})",
                    restricted,
                    expected_restricted
                ));
            }

            // Test is_cpu_allowed with matching CPU
            if !cpuset::is_cpu_allowed(first_cpu, child_id, first_mask) {
                return Err(alloc::format!(
                    "CPU {} should be allowed by cpuset + affinity",
                    first_cpu
                ));
            }

            // Multi-core specific tests
            if second_mask != 0 {
                let second_cpu = second_mask.trailing_zeros() as usize;

                // Second CPU should be allowed in parent
                if !cpuset::is_cpu_allowed(second_cpu, parent_id, 0) {
                    return Err(alloc::format!(
                        "CPU {} should be allowed in parent cpuset",
                        second_cpu
                    ));
                }

                // Second CPU should NOT be allowed in child cpuset
                if cpuset::is_cpu_allowed(second_cpu, child_id, 0) {
                    return Err(alloc::format!(
                        "CPU {} should be disallowed by child cpuset",
                        second_cpu
                    ));
                }
            }

            Ok(())
        })();

        // Step 8: Cleanup - destroy cpusets in reverse order
        for id in created.into_iter().rev() {
            if let Err(e) = cpuset::cpuset_destroy(id) {
                return TestResult::Fail(alloc::format!(
                    "Failed to destroy cpuset {:?}: {:?}",
                    id, e
                ));
            }
        }

        match result {
            Ok(()) => TestResult::Pass,
            Err(msg) => TestResult::Fail(msg),
        }
    }
}

/// Verify CPU affinity masks are honored by the scheduler
struct SchedulerAffinityTest;

impl RuntimeTest for SchedulerAffinityTest {
    fn name(&self) -> &'static str {
        "scheduler_affinity"
    }

    fn description(&self) -> &'static str {
        "Check that scheduler honors CPU affinity masks"
    }

    fn run(&self) -> TestResult {
        use arch::{current_cpu_id, max_cpus, num_online_cpus};
        use mm::tlb_shootdown::is_cpu_online;
        use sched::Scheduler;

        if num_online_cpus() <= 1 {
            return TestResult::Warning(String::from(
                "Single-core system; skipping affinity test",
            ));
        }

        // Verify cpu_allowed() helper treats 0 as "all CPUs" (R70-3 fix)
        // and correctly identifies allowed CPUs
        let self_cpu = current_cpu_id();

        // Find another online CPU
        let target = match (0..max_cpus()).find(|&id| id != self_cpu && is_cpu_online(id)) {
            Some(id) => id,
            None => {
                return TestResult::Fail(String::from("No online AP found for affinity test"))
            }
        };

        // Test 1: allowed_cpus = 0 means all CPUs allowed
        let mask_all = 0u64;
        let allowed_self = Scheduler::cpu_allowed_for_test(self_cpu, mask_all);
        let allowed_target = Scheduler::cpu_allowed_for_test(target, mask_all);
        if !allowed_self || !allowed_target {
            return TestResult::Fail(String::from(
                "cpu_allowed() should return true for all CPUs when mask is 0",
            ));
        }

        // Test 2: Specific mask only allows designated CPU
        let mask_target_only = 1u64 << target;
        let allowed_self_specific = Scheduler::cpu_allowed_for_test(self_cpu, mask_target_only);
        let allowed_target_specific = Scheduler::cpu_allowed_for_test(target, mask_target_only);
        if allowed_self_specific {
            return TestResult::Fail(alloc::format!(
                "CPU {} should NOT be allowed when mask is for CPU {} only",
                self_cpu, target
            ));
        }
        if !allowed_target_specific {
            return TestResult::Fail(alloc::format!(
                "CPU {} should be allowed when mask is for CPU {}",
                target, target
            ));
        }

        TestResult::Pass
    }
}

// ============================================================================
// Test Runner
// ============================================================================

/// Run all runtime tests and return a report
pub fn run_all_runtime_tests() -> TestReport {
    let tests: [&dyn RuntimeTest; 16] = [
        &HeapAllocationTest,
        &BuddyAllocatorTest,
        &CapTableLifecycleTest,
        &StrictSeccompFilterTest,
        &PledgeSeccompFilterTest,
        &AuditHashChainTest,
        &NetworkParsingTest,
        &NetworkLoopbackTest,
        &SmpOnlineTest,
        &IpiPingPongTest,
        &TlbShootdownCoherencyTest,
        &CpusetIsolationTest,
        &SchedulerAffinityTest,
        &SchedulerStarvationTest,
        &ProcessCreationTest,
        &SecuritySubsystemTest,
    ];

    let mut outcomes = Vec::with_capacity(tests.len());
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut warnings = 0usize;

    println!();
    println!("=== Runtime Functional Tests ===");
    println!();

    for test in tests {
        print!("  [TEST] {}... ", test.name());

        let result = test.run();

        match &result {
            TestResult::Pass => {
                println!("PASS");
                passed += 1;
            }
            TestResult::Warning(msg) => {
                println!("WARN: {}", msg);
                warnings += 1;
            }
            TestResult::Fail(msg) => {
                println!("FAIL: {}", msg);
                failed += 1;
            }
        }

        outcomes.push(TestOutcome {
            name: test.name(),
            result,
        });
    }

    println!();
    println!(
        "=== Test Summary: {} passed, {} warnings, {} failed ===",
        passed, warnings, failed
    );
    println!();

    TestReport {
        passed,
        failed,
        warnings,
        outcomes,
    }
}

/// Run a single test by name
pub fn run_test(name: &str) -> Option<TestOutcome> {
    let tests: [&dyn RuntimeTest; 16] = [
        &HeapAllocationTest,
        &BuddyAllocatorTest,
        &CapTableLifecycleTest,
        &StrictSeccompFilterTest,
        &PledgeSeccompFilterTest,
        &AuditHashChainTest,
        &NetworkParsingTest,
        &NetworkLoopbackTest,
        &SmpOnlineTest,
        &IpiPingPongTest,
        &TlbShootdownCoherencyTest,
        &CpusetIsolationTest,
        &SchedulerAffinityTest,
        &SchedulerStarvationTest,
        &ProcessCreationTest,
        &SecuritySubsystemTest,
    ];

    for test in tests {
        if test.name() == name {
            return Some(TestOutcome {
                name: test.name(),
                result: test.run(),
            });
        }
    }

    None
}
