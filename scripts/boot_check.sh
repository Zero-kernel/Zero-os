#!/bin/bash
# ============================================================================
# Zero-OS CI boot-health gate
# ============================================================================
# Unlike `make test` (which runs `timeout 10 qemu ... || true` and therefore
# ALWAYS exits 0, even on a boot crash), this script's exit code reflects real
# boot health. It boots the kernel under QEMU and asserts that:
#
#   1. the kernel reaches userspace / its idle loop (success marker on serial), and
#   2. NO NX-violation instruction-fetch #PF occurred (the D1-BOOT-NX-KASLR-LAYOUT
#      signature `v=0e e=0011` in the QEMU interrupt log).
#
# Process lesson from D1: boot health MUST be read from the serial log and the
# QEMU `-d int` log, never from the QEMU exit code.
#
# Usage:   bash scripts/boot_check.sh [esp_dir]
# Env:     OVMF_PATH (default /usr/share/qemu/OVMF.fd)
#          BOOT_CHECK_TIMEOUT seconds (default 25)
# ============================================================================
set -u

QEMU=qemu-system-x86_64
ESP="${1:-esp}"
TO="${BOOT_CHECK_TIMEOUT:-25}"

# OVMF firmware autodetect (mirrors the Makefile OVMF_PATH logic).
if [ -n "${OVMF_PATH:-}" ] && [ -f "${OVMF_PATH:-}" ]; then
    OVMF="$OVMF_PATH"
elif [ -f /usr/share/qemu/OVMF.fd ]; then
    OVMF=/usr/share/qemu/OVMF.fd
elif [ -f /usr/share/ovmf/OVMF.fd ]; then
    OVMF=/usr/share/ovmf/OVMF.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then
    OVMF=/usr/share/OVMF/OVMF_CODE.fd
else
    echo "BOOT-CHECK FAIL: OVMF firmware not found (set OVMF_PATH)"
    exit 2
fi

if [ ! -f "$ESP/kernel.elf" ]; then
    echo "BOOT-CHECK FAIL: $ESP/kernel.elf missing — run 'make build' first"
    exit 2
fi

ser="$(mktemp)"
intlog="$(mktemp)"
trap 'rm -f "$ser" "$intlog"' EXIT

# -d int,cpu_reset perturbs only host-side timing, not the guest binary/layout,
# and at boot almost no interrupts fire before [3/7], so it does not mask the
# layout-driven D1 fault while still capturing its #PF signature.
timeout "$TO" "$QEMU" -bios "$OVMF" \
    -drive format=raw,file=fat:rw:"$ESP" \
    -m 256M -vga std -no-reboot -no-shutdown \
    -cpu qemu64,+smep,+smap,+umip,+rdrand \
    -display none -serial "file:$ser" \
    -d int,cpu_reset -D "$intlog" >/dev/null 2>&1 &
qpid=$!

# Early-exit as soon as a userspace success marker appears.
reached=0
for _ in $(seq 1 $((TO * 2))); do
    sleep 0.5
    if grep -qE 'Hello from Ring 3|进入空闲循环|Process 1 exited' "$ser" 2>/dev/null; then
        reached=1
        break
    fi
    kill -0 "$qpid" 2>/dev/null || break
done
kill "$qpid" 2>/dev/null
wait "$qpid" 2>/dev/null

nx=$(grep -c 'e=0011' "$intlog" 2>/dev/null)
nx=${nx:-0}

rc=0
if [ "$nx" -gt 0 ]; then
    echo "BOOT-CHECK FAIL: $nx NX-violation #PF (D1-BOOT-NX-KASLR-LAYOUT signature v=0e e=0011)"
    grep -m1 'e=0011' "$intlog" 2>/dev/null | sed 's/^/    /'
    rc=1
fi
if [ "$reached" -ne 1 ]; then
    echo "BOOT-CHECK FAIL: kernel did not reach userspace (no Ring 3 / idle-loop marker within ${TO}s)"
    echo "--- serial tail ---"
    tail -25 "$ser" 2>/dev/null | sed 's/^/    /'
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "BOOT-CHECK OK: kernel reached userspace, 0 NX-violation faults"
fi
exit "$rc"
