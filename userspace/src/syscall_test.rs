//! Syscall Test Program for Zero-OS
//!
//! Tests the new musl-required syscalls:
//! - gettid
//! - set_tid_address
//! - set_robust_list
//! - getrandom
//! - exit_group

#![no_std]
#![no_main]

use userspace::libc::{print, print_hex, print_int, println};
use userspace::syscall::{
    is_error, sys_getpid, sys_getrandom, sys_gettid, sys_set_robust_list, sys_set_tid_address,
};

/// Test result type
struct TestResult {
    passed: usize,
    failed: usize,
}

impl TestResult {
    fn new() -> Self {
        TestResult {
            passed: 0,
            failed: 0,
        }
    }

    fn pass(&mut self, name: &str) {
        print("[PASS] ");
        println(name);
        self.passed += 1;
    }

    fn fail(&mut self, name: &str) {
        print("[FAIL] ");
        println(name);
        self.failed += 1;
    }
}

/// Program entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    println("");
    println("================================");
    println("  Zero-OS Syscall Test Suite");
    println("================================");
    println("");

    let mut results = TestResult::new();

    // Test 1: gettid
    test_gettid(&mut results);

    // Test 2: set_tid_address
    test_set_tid_address(&mut results);

    // Test 3: set_robust_list
    test_set_robust_list(&mut results);

    // Test 4: getrandom
    test_getrandom(&mut results);

    // Print summary
    println("");
    println("================================");
    print("  Results: ");
    print_int(results.passed as i64);
    print(" passed, ");
    print_int(results.failed as i64);
    println(" failed");
    println("================================");

    // Exit with appropriate code
    let exit_code = if results.failed == 0 { 0 } else { 1 };
    unsafe {
        userspace::syscall::sys_exit(exit_code);
    }
}

/// Test gettid syscall
fn test_gettid(results: &mut TestResult) {
    print("Testing gettid... ");

    unsafe {
        let tid = sys_gettid();
        let pid = sys_getpid();

        if is_error(tid) {
            results.fail("gettid returned error");
            return;
        }

        // In single-threaded mode, TID should equal PID
        if tid == pid {
            print("TID=");
            print_int(tid as i64);
            print(" ");
            results.pass("gettid");
        } else {
            print("TID=");
            print_int(tid as i64);
            print(" PID=");
            print_int(pid as i64);
            print(" ");
            results.fail("gettid: TID != PID");
        }
    }
}

/// Test set_tid_address syscall
fn test_set_tid_address(results: &mut TestResult) {
    print("Testing set_tid_address... ");

    unsafe {
        // Test with a valid pointer
        let mut tid_storage: i32 = 0;
        let ret = sys_set_tid_address(&mut tid_storage as *mut i32);

        if is_error(ret) {
            results.fail("set_tid_address returned error");
            return;
        }

        // Should return current TID
        let expected_tid = sys_gettid();
        if ret == expected_tid {
            print("returned TID=");
            print_int(ret as i64);
            print(" ");
            results.pass("set_tid_address");
        } else {
            print("got ");
            print_int(ret as i64);
            print(" expected ");
            print_int(expected_tid as i64);
            print(" ");
            results.fail("set_tid_address: wrong TID");
        }
    }
}

/// Test set_robust_list syscall
fn test_set_robust_list(results: &mut TestResult) {
    print("Testing set_robust_list... ");

    // Simulate robust_list_head structure (24 bytes)
    #[repr(C)]
    struct RobustListHead {
        list: u64,
        futex_offset: i64,
        list_op_pending: u64,
    }

    unsafe {
        let head = RobustListHead {
            list: 0,
            futex_offset: 0,
            list_op_pending: 0,
        };

        // Test with correct size (24)
        let ret = sys_set_robust_list(&head as *const _ as *const u8, 24);

        if is_error(ret) {
            let errno = -(ret as i64);
            print("errno=");
            print_int(errno);
            print(" ");
            results.fail("set_robust_list returned error");
            return;
        }

        // Test with wrong size (should fail with EINVAL)
        let ret_wrong = sys_set_robust_list(&head as *const _ as *const u8, 16);
        if is_error(ret_wrong) {
            // Expected to fail
            results.pass("set_robust_list");
        } else {
            results.fail("set_robust_list: accepted wrong size");
        }
    }
}

/// Test getrandom syscall
fn test_getrandom(results: &mut TestResult) {
    print("Testing getrandom... ");

    unsafe {
        let mut buf = [0u8; 16];
        let ret = sys_getrandom(buf.as_mut_ptr(), 16, 0);

        if is_error(ret) {
            let errno = -(ret as i64);
            print("errno=");
            print_int(errno);
            print(" ");
            results.fail("getrandom returned error");
            return;
        }

        if ret != 16 {
            print("got ");
            print_int(ret as i64);
            print(" bytes, expected 16 ");
            results.fail("getrandom: wrong byte count");
            return;
        }

        // Check that we got some non-zero bytes (very unlikely all zeros)
        let mut all_zero = true;
        for &b in buf.iter() {
            if b != 0 {
                all_zero = false;
                break;
            }
        }

        if all_zero {
            results.fail("getrandom: all bytes are zero");
        } else {
            print("got 16 random bytes: ");
            print_hex(buf[0] as u64);
            print_hex(buf[1] as u64);
            print("... ");
            results.pass("getrandom");
        }
    }
}
