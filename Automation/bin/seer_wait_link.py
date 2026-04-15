#!/usr/bin/env python3
"""Wait for a network interface link to become active.

This script:
- Brings the interface up (best effort)
- Waits for carrier or LOWER_UP state
- Enables promiscuous mode on success
- Returns success even on timeout (matches bash behavior)
"""

import os
import subprocess
import sys
import time
from typing import List


def run_best_effort(cmd: List[str]) -> subprocess.CompletedProcess:
    """Execute a command without raising exceptions.

    Mirrors bash `command || true` — failures are swallowed and indicated
    only by the non-zero return code in the result object.

    Args:
        cmd: Command and arguments.

    Returns:
        CompletedProcess result; returncode=1 and empty output on failure.
    """
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception:  # Intentional isolation point — matches bash `|| true`.
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="")


def get_carrier(iface: str) -> str:
    """Read carrier state from sysfs.

    Args:
        iface: Interface name.

    Returns:
        Carrier value: '1' (up), '0' (down), or '' if sysfs unavailable.
    """
    path = f"/sys/class/net/{iface}/carrier"
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:  # Intentional isolation point — sysfs may not exist.
        return ""


def has_lower_up(iface: str) -> bool:
    """Check if interface has LOWER_UP flag via `ip -d link show`.

    Uses -d (detail) flag to match bash: `ip -d link show "$iface"`.

    Args:
        iface: Interface name.

    Returns:
        True if LOWER_UP is present in the ip output, otherwise False.
    """
    result = run_best_effort(["ip", "-d", "link", "show", iface])
    return "LOWER_UP" in result.stdout


def main(argv: List[str]) -> int:
    """Main entry point.

    Args:
        argv: CLI arguments.

    Returns:
        Exit code; always 0 except on usage error (exit 2).
    """
    if len(argv) < 2 or not argv[1]:
        print("seer-wait-link: missing iface", file=sys.stderr)
        return 2

    iface = argv[1]

    # Priority: CLI arg > WAIT_LINK_TIMEOUT env var > 60s default (matches bash).
    if len(argv) > 2:
        raw_timeout = argv[2]
    else:
        raw_timeout = os.environ.get("WAIT_LINK_TIMEOUT", "60")

    try:
        timeout_val = int(raw_timeout)
    except Exception:  # Intentional isolation point — bad timeout falls back safely.
        timeout_val = 60

    print(
        f"seer-wait-link: bringing {iface} up and waiting for link (timeout {timeout_val}s)",
        file=sys.stderr,
    )

    # Bring interface up (best effort, matches `ip link set dev "$iface" up || true`).
    run_best_effort(["ip", "link", "set", "dev", iface, "up"])

    elapsed = 0
    while elapsed < timeout_val:
        # Prefer carrier sysfs if available (matches bash check order).
        carrier = get_carrier(iface)
        if carrier == "1":
            print(f"seer-wait-link: {iface} carrier detected", file=sys.stderr)
            run_best_effort(["ip", "link", "set", "dev", iface, "promisc", "on"])
            return 0

        # Fallback: LOWER_UP flag in ip -d link show output.
        if has_lower_up(iface):
            print(f"seer-wait-link: {iface} LOWER_UP", file=sys.stderr)
            run_best_effort(["ip", "link", "set", "dev", iface, "promisc", "on"])
            return 0

        time.sleep(1)
        elapsed += 1

    # Timeout: log and exit 0 (never fail the caller — matches bash).
    print(
        f"seer-wait-link: timed out waiting for link on {iface} (timeout {timeout_val}s); continuing",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
