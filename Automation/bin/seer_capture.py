#!/usr/bin/env python3
"""Launch tcpdump capture with rotation settings from configuration.

This script:
- Requires a network interface argument
- Loads capture settings from /opt/seer/etc/seer.yml
- Creates and prepares the PCAP ring directory
- Executes tcpdump with rotation parameters
"""

import os
import shutil
import subprocess
import sys
from typing import Any, Dict

CONFIG_PATH = "/opt/seer/etc/seer.yml"
RING_DIR = "/var/seer/pcap_ring"


def load_config(path: str) -> Dict[str, Any]:
    """Load YAML config without modifying types.

    Args:
        path: Path to YAML config file.

    Returns:
        Parsed config dict, or empty dict on any failure.
    """
    try:
        import yaml  # noqa: PLC0415

        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:  # Intentional isolation point — config is optional.
        return {}


def main(argv: list) -> int:
    """Entry point for capture script.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code; only returns on usage error or missing tcpdump.
        Replaces the process via exec on success.
    """
    if len(argv) < 2:
        print("usage: seer-capture.sh <iface>", file=sys.stderr)
        return 2

    iface = argv[1]

    cfg = load_config(CONFIG_PATH)

    # Config values are nested under 'capture:' block in seer.yml.
    # Falls back to hard defaults
    capture_cfg = cfg.get("capture", {}) or {}
    rotate = capture_cfg.get("rotate_seconds", 20)
    snaplen = capture_cfg.get("snaplen", 128)

    # Ensure ring directory exists
    try:
        os.makedirs(RING_DIR, exist_ok=True)
    except Exception:  # Intentional isolation point — directory may already exist.
        pass

    # Best-effort chown
    try:
        subprocess.run(["chown", "seer:seer", RING_DIR], check=False)
    except Exception:  # Intentional isolation point — chown failure is non-fatal.
        pass

    # Find tcpdump dynamically; exit 127 if not found.
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        print("tcpdump not found in PATH", file=sys.stderr)
        return 127

    # Build tcpdump command (no type coercion).
    # -n  : disable DNS resolution
    # -U  : packet-buffered output (write each packet immediately)
    # -Z  : drop privileges to 'seer' after opening interface
    # Filename format: SEER-%Y%m%d-%H%M%S.pcap
    cmd = [
        tcpdump,
        "-i",
        iface,
        "-n",
        "-U",
        "-s",
        str(snaplen),
        "-G",
        str(rotate),
        "-Z",
        "seer",
        "-w",
        f"{RING_DIR}/SEER-%Y%m%d-%H%M%S.pcap",
    ]

    # Replace process
    os.execvp(tcpdump, cmd)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
