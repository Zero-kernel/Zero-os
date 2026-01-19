//! Keyboard Input Driver for Zero-OS
//!
//! This module provides:
//! - PS/2 Set 1 scancode to ASCII translation
//! - Ring buffer for keyboard input
//! - Thread-safe access from interrupt handler and syscall context
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +----------------+     +-------------+
//! | Keyboard IRQ (33) | --> | push_scancode  | --> | Ring Buffer |
//! +-------------------+     +----------------+     +-------------+
//!                                                        |
//!                                                        v
//!                           +----------------+     +-------------+
//!                           | sys_read(fd=0) | <-- | read_buf    |
//!                           +----------------+     +-------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! // In keyboard interrupt handler:
//! keyboard::push_scancode(scancode);
//!
//! // In sys_read for stdin:
//! let bytes_read = keyboard::read_buf(&mut buffer);
//! ```

use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

/// Ring buffer capacity (increased to handle burst input)
const BUFFER_SIZE: usize = 1024;

/// Keyboard input ring buffer
///
/// A simple circular buffer optimized for single-producer (IRQ) and
/// single-consumer (syscall) access patterns.
pub struct KeyboardBuffer {
    /// Character buffer
    buffer: [u8; BUFFER_SIZE],
    /// Read position (consumer index)
    read_pos: usize,
    /// Write position (producer index)
    write_pos: usize,
    /// Number of characters in buffer
    count: usize,
    /// Shift key state (true if pressed)
    shift_pressed: bool,
    /// Ctrl key state (true if pressed)
    ctrl_pressed: bool,
    /// Caps Lock state (true if active)
    caps_lock: bool,
}

impl KeyboardBuffer {
    /// Create a new empty keyboard buffer
    const fn new() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            count: 0,
            shift_pressed: false,
            ctrl_pressed: false,
            caps_lock: false,
        }
    }

    /// Check if buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer is full
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= BUFFER_SIZE
    }

    /// Get number of available characters
    #[inline]
    pub fn available(&self) -> usize {
        self.count
    }

    /// Push a character into the buffer
    ///
    /// Returns true if character was added, false if buffer is full.
    fn push(&mut self, ch: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.buffer[self.write_pos] = ch;
        self.write_pos = (self.write_pos + 1) % BUFFER_SIZE;
        self.count += 1;
        true
    }

    /// Pop a character from the buffer
    ///
    /// Returns None if buffer is empty.
    fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let ch = self.buffer[self.read_pos];
        self.read_pos = (self.read_pos + 1) % BUFFER_SIZE;
        self.count -= 1;
        Some(ch)
    }

    /// Read multiple characters into a buffer
    ///
    /// Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for byte in buf.iter_mut() {
            match self.pop() {
                Some(ch) => {
                    *byte = ch;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Process a PS/2 Set 1 scancode
    ///
    /// Handles key press/release, modifier state, and character conversion.
    fn process_scancode(&mut self, scancode: u8) {
        // Check for key release (bit 7 set)
        let released = scancode & 0x80 != 0;
        let scancode = scancode & 0x7F; // Clear release bit

        // Handle modifier keys
        match scancode {
            // Left/Right Shift
            0x2A | 0x36 => {
                self.shift_pressed = !released;
                return;
            }
            // Left/Right Ctrl
            0x1D => {
                self.ctrl_pressed = !released;
                return;
            }
            // Caps Lock (toggle on press only)
            0x3A => {
                if !released {
                    self.caps_lock = !self.caps_lock;
                }
                return;
            }
            _ => {}
        }

        // Only process key presses, not releases
        if released {
            return;
        }

        // Convert scancode to ASCII
        if let Some(ch) = self.scancode_to_ascii(scancode) {
            // Handle Ctrl+C (SIGINT placeholder - push ETX)
            if self.ctrl_pressed && (ch == b'c' || ch == b'C') {
                self.push(0x03); // ETX (Ctrl+C)
                return;
            }

            // Handle Ctrl+D (EOF placeholder - push EOT)
            if self.ctrl_pressed && (ch == b'd' || ch == b'D') {
                self.push(0x04); // EOT (Ctrl+D)
                return;
            }

            self.push(ch);
        }
    }

    /// Convert PS/2 Set 1 scancode to ASCII character
    ///
    /// Returns None for non-printable keys (function keys, arrows, etc.)
    fn scancode_to_ascii(&self, scancode: u8) -> Option<u8> {
        // PS/2 Set 1 scancode to ASCII mapping
        // Layout: US QWERTY
        static SCANCODE_ASCII: [u8; 128] = [
            0, 0x1B, // 0x00: None, 0x01: Escape
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
            b'0', // 0x02-0x0B: Number row
            b'-', b'=', 0x08,  // 0x0C: -, 0x0D: =, 0x0E: Backspace
            b'\t', // 0x0F: Tab
            b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o',
            b'p', // 0x10-0x19: QWERTY row
            b'[', b']', b'\n', // 0x1A: [, 0x1B: ], 0x1C: Enter
            0,     // 0x1D: Left Ctrl (modifier)
            b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E-0x26: ASDF row
            b';', b'\'', b'`', // 0x27: ;, 0x28: ', 0x29: `
            0,    // 0x2A: Left Shift (modifier)
            b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2B-0x32: ZXCV row
            b',', b'.', b'/', // 0x33: ,, 0x34: ., 0x35: /
            0,    // 0x36: Right Shift (modifier)
            b'*', // 0x37: Keypad *
            0,    // 0x38: Left Alt
            b' ', // 0x39: Space
            0,    // 0x3A: Caps Lock (modifier)
            // 0x3B-0x44: F1-F10 (non-printable)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x45-0x46: Num Lock, Scroll Lock
            0, 0, // 0x47-0x53: Keypad and arrows (non-printable in this simple impl)
            0, 0, 0, b'-', 0, 0, 0, b'+', 0, 0, 0, 0, 0, // Rest: not mapped
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Shifted characters mapping
        static SCANCODE_ASCII_SHIFT: [u8; 128] = [
            0, 0x1B, // 0x00: None, 0x01: Escape
            b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', // Shifted numbers
            b'_', b'+', 0x08,  // 0x0C: _, 0x0D: +, 0x0E: Backspace
            b'\t', // 0x0F: Tab
            b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', // Shifted QWERTY
            b'{', b'}', b'\n', // 0x1A: {, 0x1B: }, 0x1C: Enter
            0,     // 0x1D: Left Ctrl
            b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', // Shifted ASDF
            b':', b'"', b'~', // 0x27: :, 0x28: ", 0x29: ~
            0,    // 0x2A: Left Shift
            b'|', b'Z', b'X', b'C', b'V', b'B', b'N', b'M', // Shifted ZXCV
            b'<', b'>', b'?', // 0x33: <, 0x34: >, 0x35: ?
            0,    // 0x36: Right Shift
            b'*', // 0x37: Keypad *
            0,    // 0x38: Left Alt
            b' ', // 0x39: Space
            0,    // 0x3A: Caps Lock
            // 0x3B-0x44: F1-F10 (non-printable)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x45-0x46: Num Lock, Scroll Lock
            0, 0, // 0x47-0x53: Keypad and arrows
            0, 0, 0, b'-', 0, 0, 0, b'+', 0, 0, 0, 0, 0,
            // 0x54-0x7F: Rest not mapped (44 elements)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        if scancode as usize >= SCANCODE_ASCII.len() {
            return None;
        }

        // Determine effective shift state (XOR with Caps Lock for letters)
        let use_shift = if self.is_letter_scancode(scancode) {
            self.shift_pressed ^ self.caps_lock
        } else {
            self.shift_pressed
        };

        let ch = if use_shift {
            SCANCODE_ASCII_SHIFT[scancode as usize]
        } else {
            SCANCODE_ASCII[scancode as usize]
        };

        if ch == 0 {
            None
        } else {
            Some(ch)
        }
    }

    /// Check if scancode corresponds to a letter key (affected by Caps Lock)
    fn is_letter_scancode(&self, scancode: u8) -> bool {
        matches!(
            scancode,
            0x10..=0x19 | // Q-P
            0x1E..=0x26 | // A-L
            0x2C..=0x32   // Z-M
        )
    }
}

lazy_static! {
    /// Global keyboard input buffer
    ///
    /// Protected by a spin lock for IRQ-safe access.
    static ref KEYBOARD_BUFFER: Mutex<KeyboardBuffer> = Mutex::new(KeyboardBuffer::new());
}

/// Counter for dropped bytes due to buffer full or lock contention
static DROPPED_BYTES: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Public API
// ============================================================================

/// Process a keyboard scancode from the interrupt handler
///
/// This function is called from the keyboard IRQ handler (IRQ 1).
/// It decodes the PS/2 Set 1 scancode and pushes any resulting
/// character into the keyboard buffer.
///
/// Uses blocking lock - safe because:
/// 1. IRQ handler has interrupts disabled on this CPU
/// 2. Consumer (read_buf) uses without_interrupts() before locking
/// 3. Lock hold time is very short in both cases
///
/// # Arguments
///
/// * `scancode` - Raw PS/2 Set 1 scancode from port 0x60
#[inline]
pub fn push_scancode(scancode: u8) {
    // Use blocking lock - safe in IRQ context with interrupts disabled
    let mut buffer = KEYBOARD_BUFFER.lock();
    buffer.process_scancode(scancode);
}

/// Push a raw ASCII character directly into the keyboard buffer
///
/// This function is called from the serial IRQ handler (IRQ 4)
/// for `-nographic` mode input. The character is already ASCII,
/// no scancode conversion is needed.
///
/// Uses blocking lock - safe because:
/// 1. IRQ handler has interrupts disabled on this CPU
/// 2. Consumer (read_buf) uses without_interrupts() before locking
/// 3. Lock hold time is very short in both cases
///
/// # Arguments
///
/// * `ch` - ASCII character to push
///
/// # Returns
///
/// `true` if character was pushed, `false` if buffer full
#[inline]
pub fn push_char(ch: u8) -> bool {
    // Use blocking lock - we're in IRQ context with interrupts disabled,
    // and consumers use without_interrupts() so no deadlock possible
    let mut buffer = KEYBOARD_BUFFER.lock();
    if buffer.push(ch) {
        true
    } else {
        // Buffer full
        DROPPED_BYTES.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Read characters from the keyboard buffer
///
/// Non-blocking: returns immediately with 0 if no input available.
///
/// # Arguments
///
/// * `buf` - Destination buffer for keyboard input
///
/// # Returns
///
/// Number of bytes read (0 if buffer empty)
///
/// # Note
///
/// Interrupts are disabled while holding the buffer lock to prevent
/// deadlock with the keyboard/serial interrupt handlers.
pub fn read_buf(buf: &mut [u8]) -> usize {
    // Disable interrupts to prevent deadlock with IRQ handlers
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut buffer = KEYBOARD_BUFFER.lock();
        buffer.read(buf)
    })
}

/// Read a single character from the keyboard buffer
///
/// Non-blocking: returns None if no input available.
///
/// # Returns
///
/// The next character, or None if buffer empty
pub fn read_char() -> Option<u8> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut buffer = KEYBOARD_BUFFER.lock();
        buffer.pop()
    })
}

/// Check if keyboard input is available
///
/// # Returns
///
/// true if there is at least one character in the buffer
pub fn has_input() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let buffer = KEYBOARD_BUFFER.lock();
        !buffer.is_empty()
    })
}

/// Get number of characters available in the buffer
pub fn available() -> usize {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let buffer = KEYBOARD_BUFFER.lock();
        buffer.available()
    })
}

/// Clear all buffered keyboard input
///
/// Useful for flushing stale input after mode switches.
pub fn clear() {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut buffer = KEYBOARD_BUFFER.lock();
        buffer.read_pos = 0;
        buffer.write_pos = 0;
        buffer.count = 0;
    })
}

/// Get number of characters dropped due to buffer full or lock contention
///
/// Useful for debugging input issues.
pub fn dropped_count() -> u64 {
    DROPPED_BYTES.load(Ordering::Relaxed)
}
