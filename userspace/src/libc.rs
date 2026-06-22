//! Minimal libc Implementation for Zero-OS
//!
//! This module provides essential C library functions for user-space programs:
//! - Memory operations: memcpy, memset, memcmp, memmove
//! - String operations: strlen, strcpy, strncpy, strcmp, strncmp
//! - I/O operations: putchar, puts, getchar, gets
//! - Number conversion: itoa, atoi
//!
//! # Safety
//!
//! Most functions in this module are `unsafe` as they operate on raw pointers.
//! Care must be taken to ensure pointers are valid and buffers are properly sized.

use crate::syscall::{sys_read, sys_write};

// ============================================================================
// Memory Operations
// ============================================================================

/// Copy `n` bytes from `src` to `dest`.
///
/// The memory regions must not overlap. For overlapping regions, use `memmove`.
///
/// # Safety
///
/// Both pointers must be valid for reads/writes of `n` bytes.
#[inline]
pub unsafe fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

/// Set `n` bytes starting at `dest` to value `c`.
///
/// # Safety
///
/// `dest` must be valid for writes of `n` bytes.
#[inline]
pub unsafe fn memset(dest: *mut u8, c: u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = c;
        i += 1;
    }
    dest
}

/// Compare `n` bytes of memory at `s1` and `s2`.
///
/// Returns:
/// - `0` if equal
/// - `< 0` if first differing byte in `s1` is less than `s2`
/// - `> 0` if first differing byte in `s1` is greater than `s2`
///
/// # Safety
///
/// Both pointers must be valid for reads of `n` bytes.
#[inline]
pub unsafe fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

/// Copy `n` bytes from `src` to `dest`, handling overlapping regions correctly.
///
/// # Safety
///
/// Both pointers must be valid for their respective operations.
#[inline]
pub unsafe fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) {
        // Copy forward
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    } else if (dest as usize) > (src as usize) {
        // Copy backward
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

// ============================================================================
// String Operations
// ============================================================================

/// Calculate the length of a null-terminated string.
///
/// # Safety
///
/// `s` must point to a valid null-terminated string.
#[inline]
pub unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    len
}

/// Copy a null-terminated string from `src` to `dest`.
///
/// # Safety
///
/// `src` must be null-terminated. `dest` must have enough space.
#[inline]
pub unsafe fn strcpy(dest: *mut u8, src: *const u8) -> *mut u8 {
    let mut i = 0;
    loop {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// Copy at most `n` bytes from `src` to `dest`.
///
/// If `src` is shorter than `n`, the remainder is filled with zeros.
///
/// # Safety
///
/// Both pointers must be valid for their operations.
#[inline]
pub unsafe fn strncpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    // Copy until null terminator or n bytes
    while i < n {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            i += 1;
            break;
        }
        i += 1;
    }
    // Fill remainder with zeros
    while i < n {
        *dest.add(i) = 0;
        i += 1;
    }
    dest
}

/// Compare two null-terminated strings.
///
/// Returns:
/// - `0` if equal
/// - `< 0` if `s1` < `s2`
/// - `> 0` if `s1` > `s2`
///
/// # Safety
///
/// Both strings must be null-terminated.
#[inline]
pub unsafe fn strcmp(s1: *const u8, s2: *const u8) -> i32 {
    let mut i = 0;
    loop {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b || a == 0 {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
}

/// Compare at most `n` bytes of two strings.
///
/// # Safety
///
/// Both pointers must be valid for reads.
#[inline]
pub unsafe fn strncmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b || a == 0 {
            return (a as i32) - (b as i32);
        }
        i += 1;
    }
    0
}

/// Find the first occurrence of character `c` in string `s`.
///
/// Returns a pointer to the character, or null if not found.
///
/// # Safety
///
/// `s` must be a valid null-terminated string.
#[inline]
pub unsafe fn strchr(s: *const u8, c: u8) -> *const u8 {
    let mut p = s;
    loop {
        let ch = *p;
        if ch == c {
            return p;
        }
        if ch == 0 {
            return core::ptr::null();
        }
        p = p.add(1);
    }
}

// ============================================================================
// I/O Operations
// ============================================================================

/// Write a single character to stdout.
///
/// Returns the character written, or -1 on error.
pub fn putchar(c: u8) -> i32 {
    let buf = [c];
    let result = unsafe { sys_write(1, buf.as_ptr(), 1) };
    if result == 1 {
        c as i32
    } else {
        -1
    }
}

/// Write a null-terminated string to stdout, followed by a newline.
///
/// Returns a non-negative value on success, or -1 on error.
///
/// # Safety
///
/// `s` must be a valid null-terminated string.
pub unsafe fn puts(s: *const u8) -> i32 {
    let len = strlen(s);
    let result = sys_write(1, s, len as u64);
    if result != len as u64 {
        return -1;
    }
    // Write newline
    let nl = b"\n";
    let result2 = sys_write(1, nl.as_ptr(), 1);
    if result2 != 1 {
        return -1;
    }
    0
}

/// Read a single character from stdin (non-blocking).
///
/// Returns the character read, or -1 if no input available.
pub fn getchar() -> i32 {
    let mut buf = [0u8; 1];
    let result = unsafe { sys_read(0, buf.as_mut_ptr(), 1) };
    if result == 1 {
        buf[0] as i32
    } else {
        -1
    }
}

/// Read a line from stdin into the buffer (blocking until newline or max size).
///
/// Returns the buffer pointer on success, or null on error.
/// The newline is NOT included in the buffer.
///
/// # Safety
///
/// `buf` must be valid for writes of `size` bytes.
pub unsafe fn gets_s(buf: *mut u8, size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }

    let mut i = 0;
    let max = size - 1; // Reserve space for null terminator

    while i < max {
        // Poll for input (busy-wait for now)
        let c = loop {
            let ch = getchar();
            if ch >= 0 {
                break ch as u8;
            }
            // Yield to other processes while waiting
            unsafe {
                let _ = crate::syscall::sys_yield();
            }
        };

        // Handle special characters
        match c {
            b'\n' | b'\r' => {
                // End of line
                break;
            }
            0x7F | 0x08 => {
                // Backspace
                if i > 0 {
                    i -= 1;
                    // Echo backspace sequence: backspace, space, backspace
                    putchar(0x08);
                    putchar(b' ');
                    putchar(0x08);
                }
            }
            0x03 => {
                // Ctrl+C - abort input
                *buf = 0;
                return core::ptr::null_mut();
            }
            0x04 => {
                // Ctrl+D - EOF
                if i == 0 {
                    *buf = 0;
                    return core::ptr::null_mut();
                }
                break;
            }
            _ if c >= 0x20 && c < 0x7F => {
                // Printable character
                *buf.add(i) = c;
                i += 1;
                // Echo character
                putchar(c);
            }
            _ => {
                // Ignore other control characters
            }
        }
    }

    // Null terminate
    *buf.add(i) = 0;
    // Echo newline
    putchar(b'\n');
    buf
}

// ============================================================================
// Number Conversion
// ============================================================================

/// Convert an integer to a null-terminated string.
///
/// # Arguments
///
/// * `value` - The integer to convert
/// * `buf` - Buffer to write the string (must be at least 21 bytes for i64)
/// * `base` - Number base (2-36)
///
/// Returns a pointer to the beginning of the string in the buffer.
///
/// # Safety
///
/// `buf` must be valid for writes of at least 21 bytes.
pub unsafe fn itoa(mut value: i64, buf: *mut u8, base: i32) -> *mut u8 {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    if base < 2 || base > 36 {
        *buf = 0;
        return buf;
    }

    let base = base as i64;
    let negative = value < 0;
    if negative {
        value = -value;
    }

    // Convert digits in reverse order
    let mut i = 20usize;
    *buf.add(i) = 0; // Null terminator

    if value == 0 {
        i -= 1;
        *buf.add(i) = b'0';
    } else {
        while value > 0 && i > 0 {
            i -= 1;
            *buf.add(i) = DIGITS[(value % base) as usize];
            value /= base;
        }
    }

    // Add negative sign if needed
    if negative && i > 0 {
        i -= 1;
        *buf.add(i) = b'-';
    }

    buf.add(i)
}

/// Convert an unsigned integer to a null-terminated string.
///
/// # Safety
///
/// `buf` must be valid for writes of at least 21 bytes.
pub unsafe fn utoa(mut value: u64, buf: *mut u8, base: i32) -> *mut u8 {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    if base < 2 || base > 36 {
        *buf = 0;
        return buf;
    }

    let base = base as u64;

    // Convert digits in reverse order
    let mut i = 20usize;
    *buf.add(i) = 0; // Null terminator

    if value == 0 {
        i -= 1;
        *buf.add(i) = b'0';
    } else {
        while value > 0 && i > 0 {
            i -= 1;
            *buf.add(i) = DIGITS[(value % base) as usize];
            value /= base;
        }
    }

    buf.add(i)
}

/// Convert a null-terminated string to an integer.
///
/// Skips leading whitespace and handles optional sign.
///
/// # Safety
///
/// `s` must be a valid null-terminated string.
pub unsafe fn atoi(s: *const u8) -> i64 {
    let mut p = s;
    let mut result: i64 = 0;
    let mut negative = false;

    // Skip whitespace
    while *p == b' ' || *p == b'\t' || *p == b'\n' || *p == b'\r' {
        p = p.add(1);
    }

    // Handle sign
    if *p == b'-' {
        negative = true;
        p = p.add(1);
    } else if *p == b'+' {
        p = p.add(1);
    }

    // Convert digits
    while *p >= b'0' && *p <= b'9' {
        result = result * 10 + (*p - b'0') as i64;
        p = p.add(1);
    }

    if negative {
        -result
    } else {
        result
    }
}

// ============================================================================
// Convenience Macros and Functions
// ============================================================================

/// Write a string slice to stdout.
pub fn print(s: &str) {
    unsafe {
        sys_write(1, s.as_ptr(), s.len() as u64);
    }
}

/// Write a string slice to stdout with a newline.
pub fn println(s: &str) {
    print(s);
    putchar(b'\n');
}

/// Print an integer to stdout.
pub fn print_int(value: i64) {
    let mut buf = [0u8; 21];
    unsafe {
        let s = itoa(value, buf.as_mut_ptr(), 10);
        let len = strlen(s);
        sys_write(1, s, len as u64);
    }
}

/// Print an integer to stdout with a newline.
pub fn println_int(value: i64) {
    print_int(value);
    putchar(b'\n');
}

/// Print an unsigned integer in hexadecimal.
pub fn print_hex(value: u64) {
    let mut buf = [0u8; 21];
    unsafe {
        print("0x");
        let s = utoa(value, buf.as_mut_ptr(), 16);
        let len = strlen(s);
        sys_write(1, s, len as u64);
    }
}
