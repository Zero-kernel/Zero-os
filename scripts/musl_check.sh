#!/bin/bash
# ============================================================================
# Zero-OS musl libc conformance gate  (M0 item 3 — the FIRST real gate)
# ============================================================================
# Unlike `make test` (which runs `timeout 10 qemu ... || true` and therefore
# ALWAYS exits 0, even on a crash), this script's exit code reflects the REAL
# health of the user-mode ABI: it proves that a genuine static-musl binary runs
# end-to-end (crt startup consuming the auxv, musl stdio via printf -> writev,
# and a clean process exit).
#
# It boots the kernel — which MUST be built with `--features musl_test` so the
# embedded `userspace/hello_musl.elf` is the Ring-3 init program (see
# `make build-musl-test` / `make musl-check`) — under QEMU and asserts ALL of:
#
#   1. the LIBC-ATTRIBUTABLE printf marker "42 * 2 = 84" appears on serial.
#      It is printf("%d")-formatted arithmetic from userspace/hello_musl.c, so
#      it can only be produced by musl's stdio path actually running — a raw
#      write(2) syscall cannot format it. This is the discriminator that makes
#      the gate FAIL-CLOSED if the esp instead holds the DEFAULT (native Rust
#      `hello`) kernel, which also exits 0 but never prints this line.
#   2. the test program reaches its final puts() success marker
#      "musl libc test passed!" (closes the partial-run false-pass hole where
#      only the early printf ran).
#   3. the process exits CLEANLY: "Process N ... exit code 0" on serial.
#   4. NO NX-violation instruction-fetch #PF occurred (the
#      D1-BOOT-NX-KASLR-LAYOUT signature `v=0e e=0011` in the QEMU `-d int` log).
#   5. NO kernel panic on serial.
#
# `cpu_reset` markers are captured for triage but NOT hard-gated: a healthy
# zero-baseline is not calibrated across QEMU builds (boot_check.sh likewise
# does not gate on reset). Process lesson (from D1): health MUST be read from
# the serial log and the QEMU `-d int` log, never from the QEMU exit code.
#
# Usage:   bash scripts/musl_check.sh [esp_dir]
# Env:     OVMF_PATH (autodetect fallback if unset)
#          MUSL_CHECK_TIMEOUT seconds (default 25)
# ============================================================================
set -u

QEMU=qemu-system-x86_64
ESP="${1:-esp}"
TO="${MUSL_CHECK_TIMEOUT:-25}"

# Serial markers — KEEP IN SYNC with userspace/hello_musl.c.
# Both musl markers are required (printf path AND the final puts path); checked
# as fixed strings (grep -F) so the literal '*' in the arithmetic line is not
# treated as a regex quantifier.
MUSL_PRINTF_MARKER='42 * 2 = 84'
MUSL_SUCCESS_MARKER='musl libc test passed!'
# Accept both the sys_exit ("exited with code") and reaper ("terminated with
# exit code") phrasings; the musl Ring-3 path emits the latter.
EXIT_RE='Process [0-9]+ (exited with code|terminated with exit code) 0'
PANIC_MARKER='KERNEL PANIC'
# The exact D1-BOOT-NX-KASLR-LAYOUT signature. QEMU's `-d int` logs page faults
# as `v=%02x e=%04x` (vector and error code adjacent), so matching the full
# `v=0e e=0011` scopes the count to NX instruction-fetch #PF only — a bare
# `e=0011` could false-match an unrelated exception that happens to carry error
# code 0x0011. Fixed-string (grep -F) — the tokens contain no regex metachars.
NX_RE='v=0e e=0011'
CPU_RESET_RE='cpu[_ ]reset|CPU Reset'

# OVMF firmware autodetect (prefers explicit OVMF_PATH, else mirrors the
# Makefile OVMF_PATH search order including the OVMF_CODE*.fd fallback).
if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    OVMF="$(find /usr/share/OVMF/ -type f -name 'OVMF_CODE*.fd' 2>/dev/null | head -n 1)"
    if [ -z "$OVMF" ]; then
        echo "MUSL-CHECK FAIL: OVMF firmware not found (set OVMF_PATH)"
        exit 2
    fi
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "MUSL-CHECK FAIL: $ESP/kernel.elf missing — run 'make build-musl-test' first"
    exit 2
fi

ser="$(mktemp)"
intlog="$(mktemp)"
qpid=""
cleanup() {
    if [ -n "${qpid:-}" ]; then
        kill "$qpid" 2>/dev/null || true
        wait "$qpid" 2>/dev/null || true
    fi
    rm -f "$ser" "$intlog"
}
trap cleanup EXIT

# `-d int,cpu_reset` is the same proven tracing mode used by boot_check.sh: it
# perturbs only host-side logging, not the guest binary/layout, so it captures
# the NX #PF signature without masking a real fault. Single-core, not
# timing-sensitive.
timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Observe the FULL run — do NOT early-stop once the exit marker appears. A panic
# during process teardown / zombie reap / the return to the idle loop can land
# AFTER the "exit code 0" line, so stopping at the exit marker would leave a
# panic false-pass window. We therefore break early ONLY to fail-fast on a panic
# (terminal) or if QEMU dies on its own; otherwise we let `timeout $TO` end the
# guest and evaluate the COMPLETE serial + int logs. The musl/exit markers are
# re-grepped from the final log below — program order guarantees they precede the
# exit line, so full-window observation cannot miss them.
# (Safety > Efficiency > Speed: a few seconds of extra wall-clock buys a
# fail-closed panic guarantee.)
for _ in $(seq 1 $((TO * 2))); do
    sleep 0.5
    if grep -Fq "$PANIC_MARKER" "$ser" 2>/dev/null; then
        break
    fi
    kill -0 "$qpid" 2>/dev/null || break
done

kill "$qpid" 2>/dev/null || true
wait "$qpid" 2>/dev/null || true
qpid=""

# Evaluate the final logs (do not trust only the poll flag).
has_printf=0;  grep -Fq "$MUSL_PRINTF_MARKER"  "$ser" 2>/dev/null && has_printf=1
has_success=0; grep -Fq "$MUSL_SUCCESS_MARKER" "$ser" 2>/dev/null && has_success=1
has_exit=0;    grep -qE "$EXIT_RE"             "$ser" 2>/dev/null && has_exit=1
has_panic=0;   grep -Fq "$PANIC_MARKER"        "$ser" 2>/dev/null && has_panic=1

nx=$(grep -cF "$NX_RE" "$intlog" 2>/dev/null); nx=${nx:-0}
resets=$(grep -ciE "$CPU_RESET_RE" "$intlog" 2>/dev/null); resets=${resets:-0}

rc=0
if [ "$has_printf" -ne 1 ]; then
    echo "MUSL-CHECK FAIL: libc printf marker missing (expected '$MUSL_PRINTF_MARKER')"
    echo "    => musl crt/auxv/stdio did not run to the printf stage (or esp is not the musl_test kernel)"
    rc=1
fi
if [ "$has_success" -ne 1 ]; then
    echo "MUSL-CHECK FAIL: libc success marker missing (expected '$MUSL_SUCCESS_MARKER')"
    rc=1
fi
if [ "$has_exit" -ne 1 ]; then
    echo "MUSL-CHECK FAIL: no clean exit marker within ${TO}s (expected 'Process N ... exit code 0')"
    rc=1
fi
if [ "$has_panic" -eq 1 ]; then
    echo "MUSL-CHECK FAIL: kernel panic observed on serial"
    rc=1
fi
if [ "$nx" -gt 0 ]; then
    echo "MUSL-CHECK FAIL: $nx NX-violation #PF (D1 signature '$NX_RE') during the musl run"
    grep -m1 -F "$NX_RE" "$intlog" 2>/dev/null | sed 's/^/    /'
    rc=1
fi

if [ "$rc" -ne 0 ]; then
    if [ "$resets" -gt 0 ]; then
        echo "MUSL-CHECK INFO: intlog contains $resets cpu_reset marker(s) (not hard-gated)"
        grep -im1 -E "$CPU_RESET_RE" "$intlog" 2>/dev/null | sed 's/^/    /'
    fi
    echo "--- serial tail ---"
    tail -40 "$ser" 2>/dev/null | sed 's/^/    /'
else
    if [ "$resets" -gt 0 ]; then
        echo "MUSL-CHECK OK: static-musl hello ran to exit 0 (both libc markers + clean exit + 0 NX faults; $resets cpu_reset marker(s) observed, not gated)"
    else
        echo "MUSL-CHECK OK: static-musl hello ran to exit 0 (both libc markers + clean exit + 0 NX faults)"
    fi
fi
exit "$rc"
