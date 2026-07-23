#!/bin/bash
# SPDX-License-Identifier: GPL-2.0+
# shellcheck shell=bash
#
# Shared helpers for kernel replay scripts.
# This file is meant to be sourced, not executed directly.

# Patterns that indicate an unsafe kernel reaction to a malformed image.
# Checked BEFORE the accepted/rejected markers because init may print the
# "booted" marker before later traversal triggers a BUG/Oops.
# Match actual kernel panic/BUG/oops messages.  The bare word "panic" is
# intentionally avoided because the QEMU cmdline contains "panic=-1", which
# otherwise causes every normal boot to be misclassified as PANIC.
_DANGEROUS_PATTERNS="kernel BUG|BUG:|Oops:|KASAN|KMSAN|KFENCE|UBSAN|Kernel panic|general protection fault|stack-protector|WARNING:|lockdep|INFO: task .*blocked for more than|hung task|RCU stall|rcu_sched detected stalls|Unable to handle kernel|kernel NULL pointer dereference|invalid opcode"

# Classify a QEMU dmesg log.
# Usage: classify_dmesg <dmesg_path> <qemu_rc>
# Sets: REPLAY_RESULT, REPLAY_MSG
classify_dmesg() {
    local dmesg_path="$1"
    local qemu_rc="$2"

    REPLAY_RESULT=""
    REPLAY_MSG=""

    if [[ ! -f "$dmesg_path" ]]; then
        REPLAY_RESULT="UNKNOWN"
        REPLAY_MSG="missing dmesg log"
        return
    fi

    # 1. Unsafe kernel behavior takes precedence over everything else.
    if grep -qiE "$_DANGEROUS_PATTERNS" "$dmesg_path"; then
        REPLAY_RESULT="PANIC"
        REPLAY_MSG="KERNEL BUG/OOPS/KASAN DETECTED"
        return
    fi

    # 2. Expected clean rejection.
    if grep -q "EROFS_ORACLE phase=mount status=rejected" "$dmesg_path"; then
        REPLAY_RESULT="REJECTED"
        REPLAY_MSG="mount rejected cleanly"
        return
    fi

    # 3. Acceptance is committed only after complete traversal and EOF reads.
    if grep -q "EROFS_ORACLE phase=complete status=accepted" "$dmesg_path"; then
        REPLAY_RESULT="ACCEPTED"
        REPLAY_MSG=$(grep "EROFS_ORACLE phase=traverse status=accepted" "$dmesg_path" | tail -1)
        [[ -z "$REPLAY_MSG" ]] && REPLAY_MSG="mounted and traversed successfully"
        return
    fi

    # 4. A guest-side traversal/read failure is a clean format rejection.
    if grep -qE "EROFS_ORACLE phase=(readdir|inode|read_data|traverse) status=rejected" "$dmesg_path"; then
        REPLAY_RESULT="REJECTED"
        REPLAY_MSG=$(grep -E "EROFS_ORACLE phase=(readdir|inode|read_data|traverse) status=rejected" "$dmesg_path" | tail -1)
        return
    fi

    # 5. Timeout or unknown.
    if [[ "$qemu_rc" -eq 124 ]]; then
        REPLAY_RESULT="TIMEOUT"
        REPLAY_MSG="QEMU timeout"
        return
    fi

    REPLAY_RESULT="UNKNOWN"
    REPLAY_MSG="exit_code=$qemu_rc"
}
