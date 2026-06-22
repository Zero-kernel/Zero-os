//! Zero-OS Simple Shell
//!
//! A minimal interactive shell for Zero-OS that demonstrates:
//! - Keyboard input via sys_read
//! - Command parsing
//! - Built-in commands
//!
//! ## Commands
//!
//! - `help` - Show available commands
//! - `echo <text>` - Print text to stdout
//! - `pid` - Show current process ID
//! - `ppid` - Show parent process ID
//! - `clear` - Clear screen (VGA)
//! - `exit` - Exit the shell
//!
//! ## Example Session
//!
//! ```text
//! Zero-OS Shell v0.1
//! Type 'help' for available commands.
//!
//! $ help
//! Available commands:
//!   help  - Show this help message
//!   echo  - Print text (echo <text>)
//!   pid   - Show current process ID
//!   ppid  - Show parent process ID
//!   clear - Clear screen
//!   exit  - Exit shell
//!
//! $ echo Hello, World!
//! Hello, World!
//!
//! $ pid
//! PID: 1
//!
//! $ exit
//! Goodbye!
//! ```

#![no_std]
#![no_main]

use core::{cmp, mem, ptr};
use userspace::libc::{getchar, print, print_int, println, putchar, strncmp};
use userspace::syscall::{
    is_error, parse_ipv4, sys_chdir, sys_close, sys_connect, sys_exit, sys_getcwd, sys_getdents64,
    sys_getpid, sys_getppid, sys_open, sys_read, sys_recvfrom, sys_sendto, sys_socket, sys_stat,
    sys_uname, sys_write, Dirent64, SockAddrIn, Stat, UtsName, AF_INET, IPPROTO_TCP, SOCK_STREAM,
};

/// Maximum command line length
const MAX_CMD_LEN: usize = 128;

/// Shell prompt string
const PROMPT: &str = "$ ";

/// Maximum path length
const MAX_PATH_LEN: usize = 256;

/// Read buffer size for streaming files
const READ_BUF_SIZE: usize = 512;

/// Buffer size for directory reads
const DIR_BUF_SIZE: usize = 1024;

/// Open flag: read only
const O_RDONLY: i32 = 0;

/// Open flag: open directory
const O_DIRECTORY: i32 = 0o200000;

/// Directory entry type for directories
const DT_DIR: u8 = 4;

/// Welcome banner
const BANNER: &str = "\n\
================================\n\
   Zero-OS Shell v0.1\n\
================================\n\
Type 'help' for available commands.\n\
";

/// Help message
const HELP_MSG: &str = "\
Available commands:\n\
  help  - Show this help message\n\
  echo  - Print text (echo <text>)\n\
  pid   - Show current process ID\n\
  ppid  - Show parent process ID\n\
  clear - Clear screen\n\
  ls    - List directory contents (ls [path])\n\
  cat   - Print file contents (cat <file>)\n\
  pwd   - Print current working directory\n\
  cd    - Change directory (cd <dir>)\n\
  stat  - Show file status (stat <file>)\n\
  ps    - List processes from /proc\n\
  free  - Show memory info from /proc/meminfo\n\
  tcp   - TCP client test (tcp <ip> <port> <message>)\n\
  uname - Show system information\n\
  exit  - Exit shell\n\
";

/// Program entry point
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Print welcome banner
    print(BANNER);

    // Command buffer
    let mut cmd_buf = [0u8; MAX_CMD_LEN];

    // Main shell loop
    loop {
        // Print prompt
        print(PROMPT);

        // Read command line
        let len = read_line(&mut cmd_buf);

        // Skip empty lines
        if len == 0 {
            continue;
        }

        // Parse and execute command
        execute_command(&cmd_buf[..len]);
    }
}

/// Read a line of input from stdin.
///
/// Returns the number of characters read (excluding null terminator).
fn read_line(buf: &mut [u8]) -> usize {
    let max = buf.len().saturating_sub(1);
    let mut i = 0;

    while i < max {
        // Poll for input with throttled yields to reduce syscall overhead
        let c = loop {
            let ch = getchar();
            if ch >= 0 {
                break ch as u8;
            }
            // Yield to let other processes run and reduce CPU spin
            // The kernel will reschedule us when input arrives
            unsafe {
                let _ = userspace::syscall::sys_yield();
            }
        };

        match c {
            // Enter - end of line
            b'\n' | b'\r' => {
                putchar(b'\n');
                break;
            }
            // Backspace
            0x7F | 0x08 => {
                if i > 0 {
                    i -= 1;
                    // Echo backspace sequence
                    putchar(0x08);
                    putchar(b' ');
                    putchar(0x08);
                }
            }
            // Ctrl+C - cancel line
            0x03 => {
                println("^C");
                return 0;
            }
            // Ctrl+D - EOF (exit on empty line)
            0x04 => {
                if i == 0 {
                    println("");
                    do_exit();
                }
            }
            // Printable character
            _ if c >= 0x20 && c < 0x7F => {
                buf[i] = c;
                i += 1;
                putchar(c);
            }
            // Ignore other characters
            _ => {}
        }
    }

    // Null terminate
    buf[i] = 0;
    i
}

/// Execute a command.
fn execute_command(cmd: &[u8]) {
    // Skip leading whitespace
    let cmd = skip_whitespace(cmd);

    if cmd.is_empty() || cmd[0] == 0 {
        return;
    }

    // Match commands
    unsafe {
        if strncmp(cmd.as_ptr(), b"help\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_help();
        } else if strncmp(cmd.as_ptr(), b"echo \0".as_ptr(), 5) == 0 {
            do_echo(&cmd[5..]);
        } else if strncmp(cmd.as_ptr(), b"echo\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            println(""); // echo with no args prints newline
        } else if strncmp(cmd.as_ptr(), b"pid\0".as_ptr(), 3) == 0 && is_end(cmd, 3) {
            do_pid();
        } else if strncmp(cmd.as_ptr(), b"ppid\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_ppid();
        } else if strncmp(cmd.as_ptr(), b"clear\0".as_ptr(), 5) == 0 && is_end(cmd, 5) {
            do_clear();
        } else if strncmp(cmd.as_ptr(), b"ls\0".as_ptr(), 2) == 0 && is_end(cmd, 2) {
            do_ls(&[]);
        } else if strncmp(cmd.as_ptr(), b"ls \0".as_ptr(), 3) == 0 {
            do_ls(&cmd[3..]);
        } else if strncmp(cmd.as_ptr(), b"cat \0".as_ptr(), 4) == 0 {
            do_cat(&cmd[4..]);
        } else if strncmp(cmd.as_ptr(), b"cat\0".as_ptr(), 3) == 0 && is_end(cmd, 3) {
            println("cat: missing operand");
        } else if strncmp(cmd.as_ptr(), b"pwd\0".as_ptr(), 3) == 0 && is_end(cmd, 3) {
            do_pwd();
        } else if strncmp(cmd.as_ptr(), b"cd \0".as_ptr(), 3) == 0 {
            do_cd(&cmd[3..]);
        } else if strncmp(cmd.as_ptr(), b"cd\0".as_ptr(), 2) == 0 && is_end(cmd, 2) {
            println("cd: missing operand");
        } else if strncmp(cmd.as_ptr(), b"stat \0".as_ptr(), 5) == 0 {
            do_stat(&cmd[5..]);
        } else if strncmp(cmd.as_ptr(), b"stat\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            println("stat: missing operand");
        } else if strncmp(cmd.as_ptr(), b"ps\0".as_ptr(), 2) == 0 && is_end(cmd, 2) {
            do_ps();
        } else if strncmp(cmd.as_ptr(), b"free\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_free();
        } else if strncmp(cmd.as_ptr(), b"tcp \0".as_ptr(), 4) == 0 {
            do_tcp(&cmd[4..]);
        } else if strncmp(cmd.as_ptr(), b"tcp\0".as_ptr(), 3) == 0 && is_end(cmd, 3) {
            println("tcp: usage: tcp <ip> <port> <message>");
        } else if strncmp(cmd.as_ptr(), b"uname\0".as_ptr(), 5) == 0 && is_end(cmd, 5) {
            do_uname();
        } else if strncmp(cmd.as_ptr(), b"exit\0".as_ptr(), 4) == 0 && is_end(cmd, 4) {
            do_exit();
        } else {
            // Unknown command
            print("Unknown command: ");
            print_until_space(cmd);
            println("");
            println("Type 'help' for available commands.");
        }
    }
}

/// Skip leading whitespace in a byte slice.
fn skip_whitespace(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

/// Check if position `n` in command is end of word (space, null, or end of slice).
fn is_end(cmd: &[u8], n: usize) -> bool {
    n >= cmd.len() || cmd[n] == 0 || cmd[n] == b' ' || cmd[n] == b'\t'
}

/// Print bytes until space or null terminator.
fn print_until_space(s: &[u8]) {
    for &c in s {
        if c == 0 || c == b' ' || c == b'\t' {
            break;
        }
        putchar(c);
    }
}

/// Copy first argument into buffer (null-terminated).
/// Returns the number of bytes copied (excluding null terminator).
fn copy_arg(args: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0;
    // Skip leading whitespace
    while i < args.len() && (args[i] == b' ' || args[i] == b'\t') {
        i += 1;
    }
    let mut j = 0;
    // Copy until space, null, or buffer full
    while i < args.len() && args[i] != 0 && args[i] != b' ' && args[i] != b'\t' && j + 1 < out.len()
    {
        out[j] = args[i];
        i += 1;
        j += 1;
    }
    // Null terminate
    if j < out.len() {
        out[j] = 0;
    }
    j
}

/// Print a null-terminated buffer.
fn print_cstr(buf: &[u8]) {
    for &c in buf {
        if c == 0 {
            break;
        }
        putchar(c);
    }
}

/// Get length of a name (until null or max).
fn name_length(ptr: *const u8, max: usize) -> usize {
    let mut i = 0;
    while i < max {
        let c = unsafe { *ptr.add(i) };
        if c == 0 {
            break;
        }
        i += 1;
    }
    i
}

/// Check if entry is "." or "..".
fn is_dot_entry(ptr: *const u8, max: usize) -> bool {
    let len = name_length(ptr, max);
    if len == 0 {
        return true;
    }
    if len == 1 {
        return unsafe { *ptr == b'.' };
    }
    if len == 2 {
        return unsafe { *ptr == b'.' && *ptr.add(1) == b'.' };
    }
    false
}

/// Check if name contains only digits (for ps command).
fn is_numeric_name(ptr: *const u8, max: usize) -> bool {
    let len = name_length(ptr, max);
    if len == 0 {
        return false;
    }
    let mut i = 0;
    while i < len {
        let c = unsafe { *ptr.add(i) };
        if c < b'0' || c > b'9' {
            return false;
        }
        i += 1;
    }
    true
}

/// Print name bytes.
fn print_name(ptr: *const u8, max: usize) {
    let len = name_length(ptr, max);
    for i in 0..len {
        unsafe {
            putchar(*ptr.add(i));
        }
    }
}

/// Iterate directory entries, calling visitor for each.
fn for_each_dirent<F>(fd: i32, mut visitor: F) -> bool
where
    F: FnMut(*const u8, usize, u8),
{
    let mut buf = [0u8; DIR_BUF_SIZE];
    loop {
        let nread = unsafe { sys_getdents64(fd, buf.as_mut_ptr(), buf.len()) };
        if is_error(nread) {
            return false;
        }
        if nread == 0 {
            break;
        }
        let mut offset = 0usize;
        while offset < nread as usize {
            let ptr = unsafe { buf.as_ptr().add(offset) as *const Dirent64 };
            let dirent = unsafe { core::ptr::read_unaligned(ptr) };
            if dirent.d_reclen == 0 {
                return false;
            }
            let header_size = mem::size_of::<Dirent64>();
            if (dirent.d_reclen as usize) <= header_size {
                return false;
            }
            let name_len = (dirent.d_reclen as usize).saturating_sub(header_size);
            let name_ptr = unsafe { (ptr as *const u8).add(header_size) };
            visitor(name_ptr, name_len, dirent.d_type);
            offset += dirent.d_reclen as usize;
        }
    }
    true
}

/// Stream file contents to stdout.
fn stream_file(path: *const u8) -> bool {
    let fd = unsafe { sys_open(path, O_RDONLY, 0) };
    if is_error(fd) {
        return false;
    }
    let mut buf = [0u8; READ_BUF_SIZE];
    loop {
        let n = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len() as u64) };
        if is_error(n) {
            let _ = unsafe { sys_close(fd) };
            return false;
        }
        if n == 0 {
            break;
        }
        let _ = unsafe { sys_write(1, buf.as_ptr(), n) };
    }
    let _ = unsafe { sys_close(fd) };
    true
}

// ============================================================================
// Command Implementations
// ============================================================================

/// Show help message.
fn do_help() {
    print(HELP_MSG);
}

/// Echo text to stdout.
fn do_echo(args: &[u8]) {
    let args = skip_whitespace(args);
    for &c in args {
        if c == 0 {
            break;
        }
        putchar(c);
    }
    putchar(b'\n');
}

/// Show current PID.
fn do_pid() {
    let pid = unsafe { sys_getpid() };
    print("PID: ");
    print_int(pid as i64);
    println("");
}

/// Show parent PID.
fn do_ppid() {
    let ppid = unsafe { sys_getppid() };
    print("PPID: ");
    print_int(ppid as i64);
    println("");
}

/// Clear screen (send VGA clear escape or newlines).
fn do_clear() {
    // Simple clear: print many newlines
    // A proper implementation would use ANSI escape codes or direct VGA access
    for _ in 0..25 {
        println("");
    }
}

/// Exit the shell.
fn do_exit() -> ! {
    println("Goodbye!");
    unsafe {
        sys_exit(0);
    }
}

/// List directory contents.
fn do_ls(args: &[u8]) {
    let mut path = [0u8; MAX_PATH_LEN];
    let copied = copy_arg(args, &mut path);
    if copied == 0 {
        // Default to current directory
        path[0] = b'.';
        path[1] = 0;
    }

    let fd = unsafe { sys_open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0) };
    if is_error(fd) {
        print("ls: cannot open ");
        print_cstr(&path);
        println("");
        return;
    }

    if !for_each_dirent(fd as i32, |name, len, dtype| {
        // Skip . and ..
        if is_dot_entry(name, len) {
            return;
        }
        print_name(name, len);
        if dtype == DT_DIR {
            print("/");
        }
        println("");
    }) {
        println("ls: read error");
    }

    let _ = unsafe { sys_close(fd) };
}

/// Print file contents (cat).
fn do_cat(args: &[u8]) {
    let mut path = [0u8; MAX_PATH_LEN];
    if copy_arg(args, &mut path) == 0 {
        println("cat: missing operand");
        return;
    }

    if !stream_file(path.as_ptr()) {
        print("cat: unable to read ");
        print_cstr(&path);
        println("");
    }
}

/// Print working directory.
fn do_pwd() {
    let mut buf = [0u8; MAX_PATH_LEN];
    let res = unsafe { sys_getcwd(buf.as_mut_ptr(), buf.len()) };
    if is_error(res) {
        println("pwd: failed");
        return;
    }
    print_cstr(&buf);
    println("");
}

/// Change working directory.
fn do_cd(args: &[u8]) {
    let mut path = [0u8; MAX_PATH_LEN];
    if copy_arg(args, &mut path) == 0 {
        println("cd: missing operand");
        return;
    }

    let res = unsafe { sys_chdir(path.as_ptr()) };
    if is_error(res) {
        print("cd: unable to enter ");
        print_cstr(&path);
        println("");
    }
}

/// Show file status information.
fn do_stat(args: &[u8]) {
    let mut path = [0u8; MAX_PATH_LEN];
    if copy_arg(args, &mut path) == 0 {
        println("stat: missing operand");
        return;
    }

    let mut st = Stat::default();
    let res = unsafe { sys_stat(path.as_ptr(), &mut st) };
    if is_error(res) {
        print("stat: unable to stat ");
        print_cstr(&path);
        println("");
        return;
    }

    print("  File: ");
    print_cstr(&path);
    println("");

    print("  Size: ");
    print_int(st.size as i64);
    print("  Blocks: ");
    print_int(st.blocks as i64);
    println("");

    print("Device: ");
    print_int(st.dev as i64);
    print("  Inode: ");
    print_int(st.ino as i64);
    print("  Links: ");
    print_int(st.nlink as i64);
    println("");

    print("  Mode: ");
    print_int(st.mode as i64);
    print("  Uid: ");
    print_int(st.uid as i64);
    print("  Gid: ");
    print_int(st.gid as i64);
    println("");
}

/// List processes from /proc.
fn do_ps() {
    println("  PID");
    println("-----");

    let fd = unsafe { sys_open(b"/proc\0".as_ptr(), O_RDONLY | O_DIRECTORY, 0) };
    if is_error(fd) {
        println("ps: cannot open /proc");
        return;
    }

    if !for_each_dirent(fd as i32, |name, len, _dtype| {
        // Only show numeric entries (process IDs)
        if is_numeric_name(name, len) {
            print("  ");
            print_name(name, len);
            println("");
        }
    }) {
        println("ps: read error");
    }

    let _ = unsafe { sys_close(fd) };
}

/// Show memory info from /proc/meminfo.
fn do_free() {
    if !stream_file(b"/proc/meminfo\0".as_ptr()) {
        println("free: unable to read /proc/meminfo");
    }
}

/// TCP client test: connect, send message, receive response.
///
/// Usage: tcp <ip> <port> <message>
///
/// Creates a TCP socket, connects to the specified server,
/// sends the message, waits for a response, and prints it.
fn do_tcp(args: &[u8]) {
    let mut idx = 0usize;

    // Skip leading whitespace and parse IP address
    while idx < args.len() && (args[idx] == b' ' || args[idx] == b'\t') {
        idx += 1;
    }
    let ip_start = idx;
    while idx < args.len() && args[idx] != 0 && args[idx] != b' ' && args[idx] != b'\t' {
        idx += 1;
    }
    if ip_start == idx {
        println("tcp: missing ip address");
        return;
    }
    let ip_slice = &args[ip_start..idx];

    // Parse port number
    while idx < args.len() && (args[idx] == b' ' || args[idx] == b'\t') {
        idx += 1;
    }
    let port_start = idx;
    while idx < args.len() && args[idx] != 0 && args[idx] != b' ' && args[idx] != b'\t' {
        idx += 1;
    }
    if port_start == idx {
        println("tcp: missing port");
        return;
    }
    let port_slice = &args[port_start..idx];

    // Parse message (rest of the line)
    while idx < args.len() && (args[idx] == b' ' || args[idx] == b'\t') {
        idx += 1;
    }
    let msg_start = idx;
    while idx < args.len() && args[idx] != 0 {
        idx += 1;
    }
    let msg_slice = &args[msg_start..idx];
    if msg_slice.is_empty() {
        println("tcp: missing message");
        return;
    }

    // Convert IP address
    let ip = match parse_ipv4(ip_slice) {
        Some(ip) => ip,
        None => {
            println("tcp: invalid ip address");
            return;
        }
    };

    // Convert port number
    let mut port_val: u32 = 0;
    let mut saw_digit = false;
    for &c in port_slice {
        if c == 0 || c == b' ' || c == b'\t' {
            break;
        }
        if c < b'0' || c > b'9' {
            println("tcp: invalid port number");
            return;
        }
        saw_digit = true;
        port_val = port_val * 10 + (c - b'0') as u32;
        if port_val > u16::MAX as u32 {
            println("tcp: port number too large");
            return;
        }
    }
    if !saw_digit || port_val == 0 {
        println("tcp: invalid port number");
        return;
    }
    let port = port_val as u16;

    // Create TCP socket
    print("Creating TCP socket... ");
    let sock = unsafe { sys_socket(AF_INET as i32, SOCK_STREAM as i32, IPPROTO_TCP as i32) };
    if is_error(sock) {
        println("FAILED");
        return;
    }
    println("OK");

    // Build destination address (network byte order)
    let sockaddr = SockAddrIn::new(ip, port);

    // Connect to server
    print("Connecting to ");
    for i in 0..4 {
        print_int(ip[i] as i64);
        if i < 3 {
            print(".");
        }
    }
    print(":");
    print_int(port as i64);
    print("... ");

    let conn = unsafe { sys_connect(sock as i32, &sockaddr, mem::size_of::<SockAddrIn>() as u32) };
    if is_error(conn) {
        println("FAILED");
        let _ = unsafe { sys_close(sock) };
        return;
    }
    println("CONNECTED");

    // Send message (TCP uses sendto with null dest_addr)
    print("Sending ");
    print_int(msg_slice.len() as i64);
    print(" bytes... ");

    let sent = unsafe {
        sys_sendto(
            sock as i32,
            msg_slice.as_ptr(),
            msg_slice.len(),
            0,
            ptr::null(),
            0,
        )
    };
    if is_error(sent) {
        println("FAILED");
        let _ = unsafe { sys_close(sock) };
        return;
    }
    print_int(sent as i64);
    println(" bytes sent");

    // Receive response (TCP uses recvfrom with null src_addr)
    print("Waiting for response... ");
    let mut buf = [0u8; READ_BUF_SIZE];
    let recv = unsafe {
        sys_recvfrom(
            sock as i32,
            buf.as_mut_ptr(),
            buf.len(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if is_error(recv) {
        println("FAILED");
        let _ = unsafe { sys_close(sock) };
        return;
    }

    if recv == 0 {
        println("connection closed by peer");
        let _ = unsafe { sys_close(sock) };
        return;
    }

    print_int(recv as i64);
    println(" bytes received");

    // Print response
    let received = cmp::min(recv as usize, buf.len());
    print("Response: ");
    for i in 0..received {
        putchar(buf[i]);
    }
    println("");

    // Close socket
    let _ = unsafe { sys_close(sock) };
    println("Connection closed");
}

/// Show system uname info.
fn do_uname() {
    let mut uts = UtsName::default();
    let res = unsafe { sys_uname(&mut uts as *mut UtsName) };
    if is_error(res) {
        println("uname: syscall failed");
        return;
    }

    print("System:  ");
    print_cstr(&uts.sysname);
    println("");

    print("Node:    ");
    print_cstr(&uts.nodename);
    println("");

    print("Release: ");
    print_cstr(&uts.release);
    println("");

    print("Version: ");
    print_cstr(&uts.version);
    println("");

    print("Machine: ");
    print_cstr(&uts.machine);
    println("");
}
