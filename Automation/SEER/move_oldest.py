#!/usr/bin/env python3
"""
Req3 — Move oldest closed PCAP from ring -> dest (export drive or backlog).
- Export-aware: if drive is mounted, moves to drive; else moves to backlog.
- "Closed" = file mtime older than QUIET_SECS (not being written).
- Writes a simple log line to mover_log.
"""

import os
import shutil
import time
from datetime import datetime
from pathlib import Path

import yaml

CFG = yaml.safe_load(open("/opt/seer/etc/seer.yml"))
RING = Path(CFG["ring_dir"])
BACKLOG = Path(CFG.get("backlog_dir", "/opt/seer/var/backlog"))
THRESH = int(CFG["buffer_threshold"])
LOGPATH = Path(CFG["mover_log"])
QUIET_SECS = 3  # consider file closed if not touched for >= 3s

# Export drive candidates (in priority order)
MOUNT_CANDIDATES = CFG.get("export", {}).get(
    "mount_candidates",
    ["/mnt/seer_external", "/mnt/SEER_EXT", "/media/seer_external"],
)
MIN_FREE_PCT = CFG.get("export", {}).get("min_free_pct", 2)


def log(msg: str):
    LOGPATH.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(LOGPATH, "a") as f:
        f.write(f"{ts} {msg}\n")


def detect_export_drive():
    """
    Detect writable export drive with sufficient space.
    Returns (mount_path, dest_pcap_dir) or (None, None).
    """
    for candidate in MOUNT_CANDIDATES:
        if not os.path.ismount(candidate):
            continue
        if not os.access(candidate, os.W_OK):
            continue

        try:
            stat = os.statvfs(candidate)
            free_bytes = stat.f_bavail * stat.f_frsize
            total_bytes = stat.f_blocks * stat.f_frsize
            free_pct = (free_bytes / total_bytes * 100) if total_bytes > 0 else 0

            if free_pct >= MIN_FREE_PCT:
                # Use dated subdirectory on drive
                date_dir = datetime.now().strftime("%Y%m%d")
                pcap_dir = Path(candidate) / "pcap" / date_dir
                return (candidate, pcap_dir)
        except Exception:
            continue

    return (None, None)


def closed(p: Path) -> bool:
    try:
        age = time.time() - p.stat().st_mtime
        return age >= QUIET_SECS
    except FileNotFoundError:
        return False


def pick_oldest_closed():
    files = [p for p in RING.glob("*.pcap") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime)
    for p in files:
        if closed(p):
            return p
    return None


def main():
    RING.mkdir(parents=True, exist_ok=True)
    BACKLOG.mkdir(parents=True, exist_ok=True)

    files = [p for p in RING.glob("*.pcap") if p.is_file()]
    count = len(files)
    if count < THRESH:
        log(f"[noop] ring has {count} files (< threshold {THRESH})")
        return

    target = pick_oldest_closed()
    if not target:
        log("[noop] no closed file to move")
        return

    # Determine destination: export drive (if present) or backlog
    drive_mount, drive_dest = detect_export_drive()

    if drive_dest:
        # Drive is present: move directly to drive
        drive_dest.mkdir(parents=True, exist_ok=True)
        dest_path = drive_dest / target.name
        route = f"export({drive_mount})"
    else:
        # No drive: move to backlog
        dest_path = BACKLOG / target.name
        route = "backlog"

    try:
        shutil.move(str(target), str(dest_path))
        log(f"[moved] {target.name} -> {route} ({dest_path})")
    except Exception as e:
        log(f"[error] move {target.name} -> {route}: {e}")


if __name__ == "__main__":
    main()
