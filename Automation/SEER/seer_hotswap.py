#!/usr/bin/env python3
"""
SEER Hot-Swap / Export Service
Monitors for external drive presence and manages PCAP export flow:
- When drive is present: drains backlog to drive,
  then mover writes directly to drive
- When drive is absent: mover writes to backlog, waiting for drive return
- Generates integrity manifests (SHA256) and maintains transfer log
"""

import hashlib
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

# Ensure log/state directories exist early (before configuring logging)
os.makedirs("/var/log/seer", exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/seer/hotswap.log", mode="a"),
    ],
)
log = logging.getLogger("seer-hotswap")

# Config path
CONFIG_PATH = "/opt/seer/etc/seer.yml"
LOCK_FILE = "/var/log/seer/seer-hotswap.lock"
STATE_FILE = "/var/log/seer/hotswap_state.json"


def read_config():
    """Load seer.yml configuration."""
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.error(f"Failed to read config {CONFIG_PATH}: {e}")
        return {}


def acquire_lock():
    """Ensure single instance via PID lock file."""
    os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE) as f:
                pid = int(f.read().strip())
            # Check if process is still running
            os.kill(pid, 0)
            log.error(f"Another instance is running (PID {pid})")
            return False
        except (OSError, ValueError):
            # Stale lock; remove it
            os.unlink(LOCK_FILE)

    with open(LOCK_FILE, "w") as f:
        f.write(str(os.getpid()))
    return True


def release_lock():
    """Remove PID lock file."""
    try:
        os.unlink(LOCK_FILE)
    except FileNotFoundError:
        pass


def detect_export_target(candidates, min_free_pct=2):
    """
    Detect writable external mount with sufficient space.
    Returns (mount_path, free_bytes) or (None, 0).
    """
    for candidate in candidates:
        if not os.path.ismount(candidate):
            continue
        if not os.access(candidate, os.W_OK):
            continue

        try:
            stat = os.statvfs(candidate)
            free_bytes = stat.f_bavail * stat.f_frsize
            total_bytes = stat.f_blocks * stat.f_frsize
            free_pct = (free_bytes / total_bytes * 100) if total_bytes > 0 else 0

            if free_pct >= min_free_pct:
                return (candidate, free_bytes)
        except Exception as e:
            log.warning(f"Failed to stat {candidate}: {e}")
            continue

    return (None, 0)


def compute_sha256(filepath):
    """Streaming SHA256 computation."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def is_file_active(filepath, rotate_seconds):
    """Check if file was modified recently (likely still being written)."""
    try:
        mtime = os.path.getmtime(filepath)
        age = time.time() - mtime
        return age < (rotate_seconds * 1.5)
    except Exception:
        return True  # Assume active if can't determine


def transfer_file(src, dst_dir, verify=True):
    """
    Transfer file from src to dst_dir with optional integrity check.
    Returns (success, sha256, error_msg).
    """
    try:
        os.makedirs(dst_dir, exist_ok=True)
        dst = os.path.join(dst_dir, os.path.basename(src))

        # Same filesystem: atomic rename
        if os.stat(src).st_dev == os.stat(dst_dir).st_dev:
            shutil.move(src, dst)
            sha = compute_sha256(dst) if verify else None
            return (True, sha, None)

        # Cross-filesystem: copy, verify, delete
        shutil.copy2(src, dst)
        os.sync()

        if verify:
            src_sha = compute_sha256(src)
            dst_sha = compute_sha256(dst)
            if src_sha != dst_sha:
                os.unlink(dst)
                return (
                    False,
                    None,
                    f"Checksum mismatch: {src_sha[:8]} != {dst_sha[:8]}",
                )

            # Verify success; safe to remove source
            os.unlink(src)
            return (True, src_sha, None)
        else:
            os.unlink(src)
            return (True, None, None)

    except Exception as e:
        return (False, None, str(e))


def write_manifest(directory, files_with_hashes):
    """Write MANIFEST.txt in directory with sha256 checksums."""
    manifest_path = os.path.join(directory, "MANIFEST.txt")
    try:
        with open(manifest_path, "w") as f:
            f.write("# SEER PCAP Export Manifest\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write("# Format: sha256  filename\n\n")
            for fname, sha in sorted(files_with_hashes):
                f.write(f"{sha}  {fname}\n")
        log.info(f"Wrote manifest: {manifest_path} ({len(files_with_hashes)} files)")
    except Exception as e:
        log.error(f"Failed to write manifest {manifest_path}: {e}")


def append_transfer_log(drive_root, entries):
    """Append transfer entries to TRANSFER.LOG on the drive."""
    log_path = os.path.join(drive_root, "TRANSFER.LOG")
    try:
        with open(log_path, "a") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log.error(f"Failed to append to {log_path}: {e}")


def export_batch(backlog_dir, drive_root, rotate_seconds):
    """
    Export all eligible PCAPs from backlog to drive.
    Returns (success_count, fail_count).
    """
    pcaps = sorted(Path(backlog_dir).glob("*.pcap*"))
    if not pcaps:
        return (0, 0)

    log.info(f"Found {len(pcaps)} PCAPs in backlog; starting export to {drive_root}")

    # Organize by date
    date_today = datetime.now().strftime("%Y%m%d")
    dest_dir = os.path.join(drive_root, "pcap", date_today)

    success_count = 0
    fail_count = 0
    transferred = []
    transfer_log_entries = []

    for pcap in pcaps:
        pcap_path = str(pcap)

        # Skip active files
        if is_file_active(pcap_path, rotate_seconds):
            log.debug(f"Skipping active file: {pcap.name}")
            continue

        # Transfer with verification
        success, sha, error = transfer_file(pcap_path, dest_dir, verify=True)

        entry = {
            "ts": datetime.now().isoformat(),
            "hostname": os.uname().nodename,
            "src": pcap_path,
            "dst": os.path.join(dest_dir, pcap.name),
            "size": pcap.stat().st_size if pcap.exists() else 0,
            "sha256": sha[:16] if sha else None,
            "result": "OK" if success else "VERIFY_FAIL" if "mismatch" in (error or "") else "IO_ERROR",
        }
        transfer_log_entries.append(entry)

        if success:
            log.info(f"Exported {pcap.name} → {dest_dir} (sha256={sha[:8]})")
            transferred.append((pcap.name, sha))
            success_count += 1
        else:
            log.error(f"Failed to export {pcap.name}: {error}")
            fail_count += 1

    # Write manifest for this batch
    if transferred:
        write_manifest(dest_dir, transferred)

    # Append to transfer log on drive
    if transfer_log_entries:
        append_transfer_log(drive_root, transfer_log_entries)

    return (success_count, fail_count)


def update_state(drive_present, last_export_ts, total_exported):
    """Update persistent state file."""
    state = {
        "drive_present": drive_present,
        "last_export_ts": last_export_ts,
        "total_exported": total_exported,
        "updated": datetime.now().isoformat(),
    }
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log.warning(f"Failed to write state file {STATE_FILE}: {e}")


def main_loop():
    """Main hotswap monitoring loop."""
    cfg = read_config()
    backlog_dir = cfg.get("backlog_dir", "/opt/seer/var/backlog")
    rotate_seconds = cfg.get("capture", {}).get("rotate_seconds", 20)
    mount_candidates = cfg.get("export", {}).get(
        "mount_candidates",
        ["/mnt/seer_external", "/mnt/SEER_EXT", "/media/seer_external"],
    )
    min_free_pct = cfg.get("export", {}).get("min_free_pct", 2)
    poll_interval = cfg.get("export", {}).get("poll_interval", 2)

    log.info("SEER hotswap service started")
    log.info(f"  Backlog: {backlog_dir}")
    log.info(f"  Mount candidates: {', '.join(mount_candidates)}")
    log.info(f"  Poll interval: {poll_interval}s")

    total_exported = 0
    last_drive_state = False

    while True:
        try:
            # Detect external drive
            drive_path, free_bytes = detect_export_target(mount_candidates, min_free_pct)
            drive_present = drive_path is not None

            # Drive state transition: absent → present
            if drive_present and not last_drive_state:
                log.info(f"Drive detected: {drive_path} (free: {free_bytes // (1024**2)} MB)")

                # Drain backlog to drive
                success, fail = export_batch(backlog_dir, drive_path, rotate_seconds)
                total_exported += success

                if success > 0:
                    log.info(f"Backlog drained: {success} PCAPs exported, {fail} failed")

                # Update state to show drive present
                update_state(
                    True,
                    datetime.now().isoformat() if success > 0 else None,
                    total_exported,
                )

            # Drive state transition: present → absent
            elif not drive_present and last_drive_state:
                log.info("Drive removed; mover will now stage to backlog")
                update_state(False, None, total_exported)

            # Drive remains present - update state to keep it current
            elif drive_present and last_drive_state:
                update_state(True, None, total_exported)

            last_drive_state = drive_present
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            log.info("Received interrupt; shutting down")
            break
        except Exception as e:
            log.error(f"Error in main loop: {e}", exc_info=True)
            time.sleep(poll_interval)


def main():
    """Entry point."""
    if not acquire_lock():
        sys.exit(1)

    try:
        main_loop()
    finally:
        release_lock()


if __name__ == "__main__":
    main()
