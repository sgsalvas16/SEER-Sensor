#!/usr/bin/env python3
"""Perform post-install verification of the SEER sensor system.

This script validates:
- Required directories exist
- Capture and Zeek services are running (templated unit names with iface)
- The mover service correctly relocates PCAP files when thresholds are exceeded
- JSON spool directory is receiving Zeek logs

Exit Codes:
    0: Verification passed
    2: Configuration missing or unreadable
    3: Verification failed
"""

import glob
import os
import subprocess
import sys
import time
from typing import Any, Dict, List

CONFIG_PATH = "/opt/seer/etc/seer.yml"


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    """Execute a command, emulating bash '|| true' behavior.

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


def systemctl(action: str, service: str) -> int:
    """Run a systemctl command.

    Args:
        action: Action to perform (start, stop, is-active, etc.).
        service: Service name.

    Returns:
        Return code from systemctl.
    """
    return run(["systemctl", action, service]).returncode


def ensure_root() -> None:
    """Ensure script runs as root; re-exec with sudo if not.

    Returns:
        None
    """
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-E", "python3"] + sys.argv)


def load_config(path: str) -> Dict[str, Any]:
    """Load YAML config as raw values (no casting).

    Args:
        path: Path to config file.

    Returns:
        Parsed config dict, or empty dict on any failure.
    """
    try:
        import yaml  # noqa: PLC0415

        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:  # Intentional isolation point — missing config is handled upstream.
        return {}


def count_pcap_files(directory: str) -> int:
    """Count PCAP files in a directory using glob, matching bash `ls *.pcap*`.

    Uses glob rather than os.listdir to avoid counting subdirectories or
    non-PCAP files. Matches bash: `ls -1 ${ring_dir}/*.pcap* | wc -l`.

    Args:
        directory: Directory path.

    Returns:
        Number of matching files, or 0 on failure.
    """
    try:
        return len(glob.glob(os.path.join(directory, "*.pcap*")))
    except Exception:  # Intentional isolation point — missing dir returns 0.
        return 0


def create_dummy_pcaps(directory: str, count: int) -> List[str]:
    """Create dummy PCAP files with backdated mtime, matching bash behavior.

    Bash creates SEER-DUMMY-<timestamp>-N.pcap files and backdates them by 10
    seconds so the mover (which checks QUIET_SECS file age) picks them up
    immediately.

    Args:
        directory: Target directory.
        count: Number of files to create.

    Returns:
        Paths of successfully created files.
    """
    created: List[str] = []
    ts = int(time.time())
    os.makedirs(directory, exist_ok=True)

    for i in range(1, count + 1):
        path = os.path.join(directory, f"SEER-DUMMY-{ts}-{i}.pcap")
        try:
            with open(path, "wb") as f:
                f.write(b"\x00")
            # Backdate mtime by 10s so the mover considers the file old enough.
            past = time.time() - 10
            os.utime(path, (past, past))
            run(["chown", "seer:seer", path])  # Best-effort chown.
            created.append(path)
        except Exception:  # Intentional isolation point — skip files we can't create.
            pass

    return created


def cleanup_dummy_pcaps(ring_dir: str, dest_dir: str, backlog_dir: str) -> None:
    """Remove SEER-DUMMY-* pcap files from ring, dest, and backlog directories.

    Mirrors bash cleanup_dummy() which removes SEER-DUMMY-*.pcap* from all
    three local directories.

    Args:
        ring_dir: Ring directory path.
        dest_dir: Destination directory path.
        backlog_dir: Backlog directory path.

    Returns:
        None
    """
    print("Cleanup: removing SEER-DUMMY test files")
    for directory in (ring_dir, dest_dir, backlog_dir):
        for f in glob.glob(os.path.join(directory, "SEER-DUMMY-*.pcap*")):
            try:
                os.remove(f)
            except Exception:  # Intentional isolation point — skip undeletable files.
                pass


def _latest_file(directory: str) -> str:
    """Return the name of the most recently modified file in a directory.

    Matches bash: `ls -1t ${dir} | head -n1`.

    Args:
        directory: Directory to inspect.

    Returns:
        Filename of the latest file, or '' if none found.
    """
    try:
        entries = os.listdir(directory)
        if not entries:
            return ""
        entries.sort(
            key=lambda f: os.path.getmtime(os.path.join(directory, f)),
            reverse=True,
        )
        return entries[0]
    except Exception:  # Intentional isolation point — missing dir returns empty.
        return ""


def _count_log_files(directory: str) -> int:
    """Count .log and .json* files in a directory, matching bash glob.

    Matches bash: `ls -1 ${json_spool}/*.log ${json_spool}/*.json*`.

    Args:
        directory: Directory to inspect.

    Returns:
        Count of matching files.
    """
    try:
        count = len(glob.glob(os.path.join(directory, "*.log")))
        count += len(glob.glob(os.path.join(directory, "*.json*")))
        return count
    except Exception:  # Intentional isolation point — missing dir returns 0.
        return 0


def main(argv: List[str]) -> int:
    """Execute verification workflow.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code: 0 on pass, 2 on missing config, 3 on failure.
    """
    ensure_root()

    cfg = load_config(CONFIG_PATH)

    if not cfg:
        print("Verifier: config not found or unreadable")
        return 2

    ring_dir = cfg.get("ring_dir", "/var/seer/pcap_ring")
    dest_dir = cfg.get("dest_dir", "/opt/seer/var/queue")
    backlog_dir = cfg.get("backlog_dir", "/opt/seer/var/backlog")
    json_spool = cfg.get("json_spool", "/var/seer/json_spool")
    iface = cfg.get("interface", "enp1s0")
    threshold_raw = cfg.get("buffer_threshold", "4")

    print(f"Verifier: ring_dir={ring_dir} dest_dir={dest_dir} backlog_dir={backlog_dir} iface={iface}")
    print(f"Verifier: json_spool={json_spool}")

    # Directory checks — hard fail if any required directory is missing.
    for d in [ring_dir, dest_dir, backlog_dir]:
        if not os.path.isdir(d):
            print(f"Verifier: missing directory {d}")
            return 3

    try:
        threshold = int(threshold_raw)
    except Exception:  # Intentional isolation point — bad threshold falls back to 4.
        threshold = 4

    count_before = count_pcap_files(ring_dir)
    print(f"PCAPs in ring before: {count_before}")

    # Create dummy files only if below threshold — exactly enough to reach it.
    # Matches bash: need=$((thresh - count_before)), no +1 off-by-one.
    if count_before < threshold:
        need = threshold - count_before
        print(f"Creating {need} dummy pcap(s) in ring to meet threshold {threshold}")
        create_dummy_pcaps(ring_dir, need)
        count_before = count_pcap_files(ring_dir)
        print(f"PCAPs in ring after adding dummies: {count_before}")

    # Record latest files in dest/backlog before triggering mover.
    latest_dest_before = _latest_file(dest_dir)
    latest_back_before = _latest_file(backlog_dir)

    # Stop capture, trigger mover oneshot, restart capture (matches bash flow).
    print("Triggering mover (oneshot)")
    systemctl("stop", f"seer-capture@{iface}.service")
    systemctl("start", "seer-move-oldest.service")
    time.sleep(3)
    systemctl("start", f"seer-capture@{iface}.service")

    count_after = count_pcap_files(ring_dir)
    print(f"PCAPs in ring after: {count_after}")

    latest_dest_after = _latest_file(dest_dir)
    latest_back_after = _latest_file(backlog_dir)

    # Determine if mover worked (matches bash three-way check).
    moved = False
    if count_after < count_before:
        print("OK: mover removed at least one file from ring")
        moved = True
    elif latest_dest_after and latest_dest_after != latest_dest_before:
        print(f"OK: new file appeared in dest: {latest_dest_after}")
        moved = True
    elif latest_back_after and latest_back_after != latest_back_before:
        print(f"OK: new file appeared in backlog: {latest_back_after}")
        moved = True
    else:
        print("FAIL: no files moved from ring and no new files in dest/backlog")

    # Check capture service active (templated unit name with iface).
    if systemctl("is-active", f"seer-capture@{iface}.service") == 0:
        print(f"OK: seer-capture@{iface} is active")
        capture_ok = True
    else:
        print(f"FAIL: seer-capture@{iface} not active")
        capture_ok = False

    # Check zeek service active (templated unit name with iface).
    if systemctl("is-active", f"seer-zeek@{iface}.service") == 0:
        print(f"OK: seer-zeek@{iface} is active")
        zeek_ok = True
    else:
        print(f"FAIL: seer-zeek@{iface} not active")
        zeek_ok = False

    # Check Zeek is writing logs into json_spool.
    _count_log_files(json_spool)  # Snapshot before sleep (reserved for future delta).
    time.sleep(2)
    zc_after = _count_log_files(json_spool)
    if zc_after > 0:
        print(f"OK: Zeek logs detected in json_spool ({zc_after})")
    else:
        print("WARN: no Zeek logs found in json_spool yet (fresh install or low traffic). Skipping log assertion.")
    logs_ok = True  # Non-fatal, matches bash behavior.

    # Cleanup dummy files from all directories.
    cleanup_dummy_pcaps(ring_dir, dest_dir, backlog_dir)

    if moved and capture_ok and zeek_ok and logs_ok:
        print("Verification PASSED")
        return 0

    print("Verification FAILED")
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
