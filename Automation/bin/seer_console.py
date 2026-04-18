#!/usr/bin/env python3
# SEER Split-Panel Console (Python, curses)
import argparse
import curses
import glob
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# -------- Config (override via env) --------
REFRESH = float(os.environ.get("REFRESH", "0.5"))
# NOTE: capture service is templated; default is derived
# from YAML 'interface' (overridable via env)
CAPTURE_SERVICE = os.environ.get("CAPTURE_SERVICE", None) or "seer-capture@enp1s0.service"
MOVER_SERVICE = os.environ.get("MOVER_SERVICE", "seer-move-oldest.service")
MOVER_TIMER = os.environ.get("MOVER_TIMER", "seer-move-oldest.timer")

BUFF_DIR = os.environ.get("BUFF_DIR", "/var/seer/pcap_ring")
MGR_LOG_HINT = os.environ.get("MGR_LOG", "/var/log/seer/mover.log")
JSON_SPOOL = os.environ.get("JSON_SPOOL", "/var/seer/json_spool")
SHIPPER_SERVICE = os.environ.get("SHIPPER_SERVICE", "seer-shipper.service")
AGENT_SERVICE = os.environ.get("AGENT_SERVICE", "seer-agent.service")
HOTSWAP_SERVICE = os.environ.get("HOTSWAP_SERVICE", "seer-hotswap.service")
HOTSWAP_STATE = os.environ.get("HOTSWAP_STATE", "/var/log/seer/hotswap_state.json")
RECEIVER_SERVICE = os.environ.get("RECEIVER_SERVICE", "seer-scout-receiver.service")
RECEIVER_PORT = int(os.environ.get("RECEIVER_PORT", "8080"))

# CLI / env flags
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument(
    "--no-colors",
    dest="no_colors",
    action="store_true",
    help="Disable colors in the TUI",
)
parser.add_argument(
    "--once",
    dest="once",
    action="store_true",
    help="Print a one-shot textual status and exit",
)
_args, _unknown = parser.parse_known_args()
NO_COLORS = bool(_args.no_colors) or os.environ.get("NO_COLORS", "0") in (
    "1",
    "true",
    "True",
)


def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def read_cfg():
    """Read /opt/seer/etc/seer.yml if present and return dict; safe fallback."""
    path = "/opt/seer/etc/seer.yml"
    try:
        import yaml

        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg
    except Exception:
        return {}


# Load config early so we can honor json_spool path from YAML
_CFG_BOOT = read_cfg()
if isinstance(_CFG_BOOT, dict):
    JSON_SPOOL = _CFG_BOOT.get("json_spool", JSON_SPOOL) or JSON_SPOOL
    _IFACE_BOOT = _CFG_BOOT.get("interface", "enp2s0")
    # If CAPTURE_SERVICE not explicitly set via env, derive from YAML
    if os.environ.get("CAPTURE_SERVICE") in (None, ""):
        CAPTURE_SERVICE = f"seer-capture@{_IFACE_BOOT}.service"


def systemctl_is_active(unit):
    if not unit:
        return "inactive"
    r = run(["systemctl", "is-active", unit])
    s = (r.stdout or r.stderr or "").strip()
    return s if s else "inactive"


def badge_text(state):
    s = (state or "").lower()
    if s == "active":
        return ("active", 2)
    if s == "failed":
        return ("FAILED", 1)
    if s in ("inactive", "dead"):
        return ("stopped", 3)
    if s.startswith("activat"):
        return ("starting", 3)
    return (s or "n/a", 3)


def count_pcaps(path):
    try:
        return sum(1 for _ in glob.glob(os.path.join(path, "*.pcap*")))
    except Exception:
        return 0


def read_hotswap_state():
    """Read hotswap state file for export drive status."""
    try:
        with open(HOTSWAP_STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def get_receiver_stats():
    """Fetch Scout Receiver statistics from HTTP endpoint."""
    try:
        import urllib.request

        url = f"http://localhost:{RECEIVER_PORT}/api/statistics"
        with urllib.request.urlopen(url, timeout=2) as r:
            return json.load(r)
    except Exception:
        return None


def json_stats(path):
    """Return (file_count, total_bytes, last_mtime_epoch) for JSON/log files.
    - Searches recursively to handle both flat and dated subdirs.
    - Matches Zeek's common patterns: *.log (JSON content) and *.json*.
    """
    try:
        patterns = ["**/*.json*", "**/*.log", "**/*.log.json*"]
        seen = set()
        total = 0
        last_m = 0.0
        for pat in patterns:
            for p in glob.glob(os.path.join(path, pat), recursive=True):
                if os.path.isdir(p):
                    continue
                if p in seen:
                    continue
                seen.add(p)
                try:
                    st = os.stat(p)
                    total += st.st_size
                    if st.st_mtime > last_m:
                        last_m = st.st_mtime
                except FileNotFoundError:
                    pass
        return (len(seen), total, last_m)
    except Exception:
        return (0, 0, 0.0)


def human_bytes(n):
    if not isinstance(n, (int, float)) or n is None:
        return "n/a"
    u = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    v = float(n)
    while v >= 1024 and i < len(u) - 1:
        v /= 1024
        i += 1
    return f"{v:.1f} {u[i]}"


def human_ago(epoch_ts):
    if not epoch_ts:
        return "n/a"
    dt = max(0, time.time() - float(epoch_ts))
    if dt < 1:
        return "<1s"
    if dt < 60:
        return f"{int(dt)}s"
    m, s = divmod(int(dt), 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


def safe_addstr(stdscr, y, x, text, attr=0):
    """Safely add string to screen, ignoring errors if out of bounds."""
    try:
        h, w = stdscr.getmaxyx()
        if y < h - 1 and x < w - 1:
            # Truncate text to fit in window
            max_len = w - x - 1
            if len(text) > max_len:
                text = text[:max_len]
            if attr:
                stdscr.addstr(y, x, text, attr)
            else:
                stdscr.addstr(y, x, text)
    except curses.error:
        pass  # Ignore curses errors


def draw_text(stdscr, y, x, w, text):
    try:
        h, width = stdscr.getmaxyx()
        if y < h and x < width:
            safe_text = (text[:w]).ljust(w)[: width - x - 1]
            stdscr.addstr(y, x, safe_text)
    except curses.error:
        pass  # Ignore curses errors from writing outside bounds


def divider(stdscr, y, width, ch="-"):
    try:
        h, w = stdscr.getmaxyx()
        if y < h:
            stdscr.addstr(y, 0, (ch * width)[: min(width, w - 1)])
    except curses.error:
        pass


def act_stop():
    units = [CAPTURE_SERVICE, MOVER_SERVICE]
    if MOVER_TIMER:
        units.append(MOVER_TIMER)
    if HOTSWAP_SERVICE:
        units.append(HOTSWAP_SERVICE)
    run(["systemctl", "stop", *units])


def act_clear(buff_dir):
    os.makedirs(buff_dir, exist_ok=True)
    cfg = read_cfg()
    dirs = [buff_dir]
    dirs.append(cfg.get("dest_dir", "/opt/seer/var/queue"))
    dirs.append(cfg.get("backlog_dir", "/opt/seer/var/backlog"))
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        for p in glob.glob(os.path.join(d, "*.pcap*")):
            try:
                os.unlink(p)
            except Exception:
                pass


def act_start():
    run(["systemctl", "daemon-reload"])
    # Restart capture service
    if CAPTURE_SERVICE:
        r = run(["systemctl", "restart", CAPTURE_SERVICE])
        if r.returncode != 0:
            run(["systemctl", "start", CAPTURE_SERVICE])

    # Restart timer (not the service - timer manages service activation)
    if MOVER_TIMER:
        r = run(["systemctl", "restart", MOVER_TIMER])
        if r.returncode != 0:
            run(["systemctl", "start", MOVER_TIMER])

    # Restart hotswap service
    if HOTSWAP_SERVICE:
        r = run(["systemctl", "restart", HOTSWAP_SERVICE])
        if r.returncode != 0:
            run(["systemctl", "start", HOTSWAP_SERVICE])


def act_toggle_mount():
    """Toggle mount/unmount of export drive.
    Fully automated - finds and mounts entire drive."""
    cfg = read_cfg()
    mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
    target = mount_candidates[0] if mount_candidates else "/mnt/seer_external"

    # Check if target is currently mounted
    if os.path.ismount(target):
        # Unmount - sync first to ensure data is written
        run(["sync"])
        result = run(["sudo", "umount", target])
        if result.returncode == 0:
            return f"✓ Unmounted {target}"
        else:
            # If busy, try lazy unmount
            if "busy" in result.stderr.lower():
                lazy_result = run(["sudo", "umount", "-l", target])
                if lazy_result.returncode == 0:
                    return f"✓ Unmounted {target} (lazy - will complete when files close)"
            return f"✗ Failed to unmount {target}: {result.stderr.strip()}"

    # Not mounted - try to mount
    # Strategy: Find external drives by checking:
    # 1. /dev/sd[b-z] (non-system disks)
    # 2. Removable flag (RM=1)
    # 3. USB connection (check /sys path)
    # 4. Has filesystem

    result = run(["lsblk", "-nrbo", "NAME,SIZE,TYPE,RM,MOUNTPOINT,FSTYPE"])

    candidates = []

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue

        dev_name = parts[0]
        size = int(parts[1]) if parts[1].isdigit() else 0
        dev_type = parts[2]
        removable = parts[3]

        # Parse optional mountpoint and fstype
        # When no mountpoint, fstype shifts left
        mountpoint = ""
        fstype = ""
        if len(parts) >= 5:
            # Could be mountpoint or fstype
            if parts[4] in (
                "ext4",
                "ext3",
                "ext2",
                "xfs",
                "btrfs",
                "ntfs",
                "vfat",
                "exfat",
                "fat32",
            ):
                fstype = parts[4]
            else:
                mountpoint = parts[4]
                fstype = parts[5] if len(parts) > 5 else ""

        # Skip if already mounted
        if mountpoint:
            continue

        # Skip system disk (sda)
        if dev_name.startswith("sda"):
            continue

        # Only consider disks (not partitions, loop, etc)
        if dev_type != "disk":
            continue

        # Strategy: Accept any non-sda disk with a filesystem
        # This includes USB-SATA cradles, external drives, etc.

        # Prioritize: sdb* > removable > has filesystem > large
        priority = 0

        # Highest priority: /dev/sdb (most common external drive)
        if dev_name.startswith("sdb"):
            priority = 10
        # Medium priority: marked as removable
        elif removable == "1":
            priority = 5
        # Low priority: has filesystem and large enough
        elif fstype and size > 1000000000:  # >1GB with filesystem
            priority = 3
        # Fallback: any disk over 1GB (even without filesystem shown)
        elif size > 1000000000:
            priority = 1

        if priority > 0:
            candidates.append((priority, size, dev_name, dev_type))

    if not candidates:
        # Debug: show what we found
        debug_info = run(["lsblk", "-o", "NAME,SIZE,TYPE,RM,FSTYPE,MOUNTPOINT"])
        return f"✗ No suitable drive found\n\nAvailable devices:\n{debug_info.stdout}"

    # Sort by priority (highest first), then size (largest first)
    candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    best_device = candidates[0][2]
    device_path = f"/dev/{best_device}"

    # Ensure mount point exists
    os.makedirs(target, exist_ok=True)

    # Try to mount - first check if device exists
    if not os.path.exists(device_path):
        return f"✗ Device {device_path} not found"

    # Check if device has a filesystem
    blkid_result = run(["sudo", "blkid", device_path])
    if blkid_result.returncode != 0:
        return f"✗ No filesystem detected on {device_path}. Use: sudo mkfs.ext4 {device_path}"

    # Try to mount
    mount_result = run(["sudo", "mount", device_path, target])

    if mount_result.returncode == 0:
        # Fix permissions so seer user can write
        run(["sudo", "chown", "seer:seer", target])
        run(["sudo", "chmod", "755", target])

        # Get size info
        df_result = run(["df", "-h", target])
        size_info = ""
        if df_result.returncode == 0:
            lines = df_result.stdout.strip().split("\n")
            if len(lines) > 1:
                fields = lines[1].split()
                if len(fields) >= 2:
                    size_info = f" ({fields[1]} total)"

        return f"✓ Mounted {device_path} at {target}{size_info}"
    else:
        error_msg = mount_result.stderr.strip()
        # Provide helpful hints based on error
        if "already mounted" in error_msg.lower():
            return f"✗ {device_path} is already mounted elsewhere"
        elif "special device" in error_msg.lower():
            return f"✗ Device {device_path} not found or not accessible"
        elif "wrong fs type" in error_msg.lower():
            return f"✗ Filesystem type not recognized. Try: sudo blkid {device_path}"
        else:
            return f"✗ Mount failed: {error_msg if error_msg else 'unknown error'}"


def collect_status():
    """Gather a snapshot of service/file metrics for one-shot output."""
    cap_state = systemctl_is_active(CAPTURE_SERVICE)
    mov_state = systemctl_is_active(MOVER_SERVICE)
    tim_state = systemctl_is_active(MOVER_TIMER) if MOVER_TIMER else "n/a"
    hot_state = systemctl_is_active(HOTSWAP_SERVICE)
    recv_state = systemctl_is_active(RECEIVER_SERVICE)

    # Prefer interface from YAML; fall back to env IFACE or enp2s0
    iface = None
    try:
        iface = _IFACE_BOOT  # set at import from read_cfg()
    except NameError:
        iface = None
    if not iface:
        iface = os.environ.get("IFACE", "enp2s0")
    zeek_unit = f"seer-zeek@{iface}.service"
    zeek_state = systemctl_is_active(zeek_unit)

    cfg = read_cfg()
    ring_dir = cfg.get("ring_dir", "/var/seer/pcap_ring")
    dest_dir = cfg.get("dest_dir", "/opt/seer/var/queue")
    backlog_dir = cfg.get("backlog_dir", "/opt/seer/var/backlog")

    buff_count = count_pcaps(ring_dir)
    dest_count = count_pcaps(dest_dir)
    back_count = count_pcaps(backlog_dir)
    j_count, j_bytes, j_last = json_stats(JSON_SPOOL)

    # Read hotswap export state
    hs_state = read_hotswap_state()
    drive_present = hs_state.get("drive_present", False)
    last_export = hs_state.get("last_export_ts", None)
    total_exported = hs_state.get("total_exported", 0)

    # Get Scout Receiver stats
    recv_stats = get_receiver_stats()

    return {
        "cap_state": cap_state,
        "mov_state": mov_state,
        "tim_state": tim_state,
        "zeek_state": zeek_state,
        "hot_state": hot_state,
        "recv_state": recv_state,
        "ring_dir": ring_dir,
        "dest_dir": dest_dir,
        "backlog_dir": backlog_dir,
        "buff_count": buff_count,
        "dest_count": dest_count,
        "back_count": back_count,
        "json": {"count": j_count, "bytes": j_bytes, "last": j_last},
        "export": {
            "drive_present": drive_present,
            "last_export_ts": last_export,
            "total_exported": total_exported,
        },
        "receiver": recv_stats,
    }


def show_help(stdscr):
    """Display full help screen with all controls."""
    curses.curs_set(0)
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    help_lines = [
        "SEER CONSOLE - CONTROLS",
        "",
        "SYSTEM:",
        "  [1] Stop All Services",
        "  [3] Start/Restart Services",
        "  [z] Start Zeek",
        "  [x] Stop Zeek",
        "",
        "EXPORT:",
        "  [2] Toggle Mount/Unmount Drive",
        "",
        "LOGS:",
        "  [c] Capture Logs",
        "  [m] Mover Logs",
        "  [h] Hotswap Logs",
        "  [r] Receiver Logs",
        "  [s] Service Status",
        "",
        "DISPLAY:",
        "  [+] Refresh Faster",
        "  [-] Refresh Slower",
        "",
        "OTHER:",
        "  [?] Show This Help",
        "  [q] Quit",
        "",
        "Press any key to return...",
    ]

    for i, line in enumerate(help_lines):
        if i < h - 1:
            stdscr.addstr(i, 2, line[: w - 4])

    stdscr.refresh()
    stdscr.nodelay(False)
    stdscr.getch()
    stdscr.nodelay(True)


def render(stdscr):
    global REFRESH
    curses.curs_set(0)
    stdscr.nodelay(True)

    # Check terminal size - use compact mode for small screens
    h, w = stdscr.getmaxyx()
    compact_mode = h < 20 or w < 60

    if h < 12 or w < 40:
        # Too small even for compact mode
        stdscr.clear()
        stdscr.addstr(0, 0, "Terminal too small!")
        stdscr.addstr(1, 0, f"Current: {h}x{w}")
        stdscr.addstr(2, 0, "Minimum: 12x40")
        stdscr.addstr(3, 0, "Resize and restart")
        stdscr.refresh()
        stdscr.getch()
        return

    if curses.has_colors() and not NO_COLORS:
        curses.start_color()
        try:
            curses.use_default_colors()
        except Exception:
            pass

        # Allow selecting a theme via environment variable
        # for easy operator control.
        # SEER_THEME=evr  -> EVR:RDY palette (teal-like active colors)
        # SEER_THEME=classic -> original classic palette (green/yellow/cyan)
        theme = os.environ.get("SEER_THEME", "evr").lower()
        try:
            if theme == "classic":
                # classic terminal-friendly mapping
                curses.init_pair(1, curses.COLOR_RED, -1)  # failed
                curses.init_pair(2, curses.COLOR_GREEN, -1)  # active
                curses.init_pair(3, curses.COLOR_YELLOW, -1)  # neutral
                curses.init_pair(4, curses.COLOR_CYAN, -1)  # header/accent
                curses.init_pair(5, curses.COLOR_WHITE, -1)  # normal
            else:
                # EVR:RDY-friendly mapping (term-safe approximation)
                curses.init_pair(1, curses.COLOR_RED, -1)  # failed/error
                curses.init_pair(2, curses.COLOR_CYAN, -1)  # active/connected (teal-like)
                curses.init_pair(3, curses.COLOR_MAGENTA, -1)  # inactive/stopped (muted)
                curses.init_pair(4, curses.COLOR_BLUE, -1)  # header/accent
                curses.init_pair(5, curses.COLOR_WHITE, -1)  # normal
        except curses.error:
            # Fallback to a basic mapping using black
            # background if default colors unsupported
            try:
                curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
                curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
                curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
                curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
                curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)
            except Exception:
                pass

    last_key = ""
    status_message = ""  # For displaying action results
    status_message_time = 0  # Timestamp when message was set
    # rolling stats for JSON write rate estimation
    last_json_bytes = None
    last_json_ts = None

    def handle_winch(signum, frame):
        curses.resizeterm(*stdscr.getmaxyx())

    signal.signal(signal.SIGWINCH, handle_winch)
    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()

        host = os.uname().nodename
        now = datetime.now()

        # Gather data
        cap_state = systemctl_is_active(CAPTURE_SERVICE)
        mov_state = systemctl_is_active(MOVER_SERVICE)
        tim_state = systemctl_is_active(MOVER_TIMER) if MOVER_TIMER else "n/a"
        hot_state = systemctl_is_active(HOTSWAP_SERVICE)

        # Prefer interface from YAML; fall back to env IFACE or enp2s0
        iface = _IFACE_BOOT if "_IFACE_BOOT" in globals() else os.environ.get("IFACE", "enp2s0")
        zeek_unit = f"seer-zeek@{iface}.service"
        zeek_state = systemctl_is_active(zeek_unit)

        buff_count = count_pcaps(BUFF_DIR)

        cfg = read_cfg()
        backlog_dir = cfg.get("backlog_dir", "/opt/seer/var/backlog")
        back_count = count_pcaps(backlog_dir)
        j_count, j_bytes, j_last = json_stats(JSON_SPOOL)

        # Read hotswap export state
        hs_state = read_hotswap_state()
        drive_present = hs_state.get("drive_present", False)

        # Count actual files on drive if mounted
        drive_pcap_count = 0
        if drive_present:
            mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
            for candidate in mount_candidates:
                if os.path.ismount(candidate):
                    try:
                        drive_pcap_count = sum(1 for _ in Path(candidate).rglob("*.pcap*"))
                    except OSError:
                        pass
                    break

        # Check if we should use compact mode (small screen)
        if compact_mode or h < 20 or w < 60:
            # COMPACT MODE - Show only PCAP info
            hdr = f"SEER [{now.strftime('%H:%M:%S')}]"
            draw_text(stdscr, 0, 0, w, hdr)
            divider(stdscr, 1, w)

            safe_addstr(stdscr, 2, 0, "PCAP:")
            safe_addstr(stdscr, 3, 2, f"Ring    : {buff_count}")
            safe_addstr(stdscr, 4, 2, f"Backlog : {back_count}")

            # Drive status
            if drive_present:
                mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
                active_mount = "drive"
                for candidate in mount_candidates:
                    if os.path.ismount(candidate):
                        active_mount = candidate
                        break
                safe_addstr(
                    stdscr,
                    5,
                    2,
                    "Drive   : ",
                    curses.color_pair(2) if curses.has_colors() else 0,
                )
                safe_addstr(stdscr, 5, 12, "CONNECTED")
                safe_addstr(stdscr, 6, 2, f"Mount   : {active_mount[: w - 12]}")
                safe_addstr(stdscr, 7, 2, f"On Drive: {drive_pcap_count} files")
            else:
                safe_addstr(
                    stdscr,
                    5,
                    2,
                    "Drive   : ",
                    curses.color_pair(3) if curses.has_colors() else 0,
                )
                safe_addstr(stdscr, 5, 12, "not connected")

            divider(stdscr, 8, w)
            safe_addstr(stdscr, 9, 0, "[2] Mount/Unmount  [q] Quit")

            # Show status message if recent (within 5 seconds)
            if status_message and (time.time() - status_message_time < 5):
                safe_addstr(stdscr, 10, 0, f"Status: {status_message[: w - 8]}")
            else:
                safe_addstr(stdscr, 10, 0, f"Input: {last_key}")

            stdscr.refresh()

            # Handle input (simplified for compact mode)
            t_end = time.time() + REFRESH
            while time.time() < t_end:
                try:
                    ch = stdscr.getch()
                except curses.error:
                    ch = -1
                if ch == -1:
                    time.sleep(0.02)
                    continue
                if ch in (ord("q"), ord("Q")):
                    return
                last_key = chr(ch) if 32 <= ch < 127 else f"[{ch}]"

                if ch == ord("2"):
                    # Mount/Unmount drive toggle - stay in console
                    status_message = "Processing..."
                    stdscr.refresh()
                    msg = act_toggle_mount()
                    status_message = msg
                    status_message_time = time.time()
                break
            continue  # Skip full mode rendering

        # FULL MODE - Show everything
        ts = now.strftime("%H:%M:%S  %b %d %Y")
        hdr = f"SEER MONITOR  [REF: {REFRESH:.1f}s]  [HOST: {host}]  [TIME: {ts}]"
        # Header: bold + accent color (pair 4)
        try:
            safe_addstr(stdscr, 0, 0, hdr, curses.color_pair(4) | curses.A_BOLD)
        except Exception:
            draw_text(stdscr, 0, 0, w, hdr)
        divider(stdscr, 1, w)
        divider(stdscr, 1, w)

        # compute a simple write rate (bytes/sec) over the last refresh
        _rate_txt = "n/a"
        now_ts = time.time()
        if last_json_bytes is not None and last_json_ts is not None:
            dt = max(0.001, now_ts - last_json_ts)
            dbytes = max(0, j_bytes - last_json_bytes)
            bps = dbytes / dt
            # show per-minute if rate is low, else per-second
            if bps < 1024:
                _rate_txt = f"{human_bytes(bps * 60)}/min"
            else:
                _rate_txt = f"{human_bytes(bps)}/s"
        last_json_bytes = j_bytes
        last_json_ts = now_ts

        left_w = w // 2 - 1
        right_w = w - left_w - 3
        # Section titles: bold + header color
        sec_left = f"+ SYSTEM {'-' * (max(0, left_w - 10))}"
        sec_right = f"+ CONTROLS {'-' * (max(0, right_w - 12))}"
        try:
            safe_addstr(stdscr, 2, 0, sec_left, curses.color_pair(4) | curses.A_BOLD)
            safe_addstr(
                stdscr,
                2,
                left_w + 1,
                sec_right,
                curses.color_pair(4) | curses.A_BOLD,
            )
        except Exception:
            draw_text(stdscr, 2, 0, left_w, sec_left)
            draw_text(stdscr, 2, left_w + 1, right_w, sec_right)
        for r in range(3, 12):
            if left_w < w:
                stdscr.addstr(r, left_w, "|")

        s, c = badge_text(cap_state)
        stdscr.addstr(3, 2, "  CAPTURE : ")
        try:
            attr = curses.color_pair(c) | (curses.A_BOLD if c == 2 else 0)
        except Exception:
            attr = curses.A_BOLD if c == 2 else 0
        stdscr.addstr(3, 14, s, attr)
        s, c = badge_text(mov_state)
        stdscr.addstr(4, 2, "  MOVER   : ")
        try:
            attr = curses.color_pair(c) | (curses.A_BOLD if c == 2 else 0)
        except Exception:
            attr = curses.A_NORMAL
        stdscr.addstr(4, 14, s, attr)
        stdscr.addstr(5, 2, f"  TIMER   : {tim_state}")
        stdscr.addstr(6, 2, f"  ZEEK    : {zeek_state}")
        s, c = badge_text(hot_state)
        stdscr.addstr(7, 2, "  HOTSWAP : ")
        try:
            attr = curses.color_pair(c) | (curses.A_BOLD if c == 2 else 0)
        except Exception:
            attr = curses.A_NORMAL
        stdscr.addstr(7, 14, s, attr)

        # Scout Receiver service status
        recv_state = systemctl_is_active(RECEIVER_SERVICE)
        s, c = badge_text(recv_state)
        stdscr.addstr(8, 2, "  RECEIVER: ")
        try:
            attr = curses.color_pair(c) | (curses.A_BOLD if c == 2 else 0)
        except Exception:
            attr = curses.A_NORMAL
        stdscr.addstr(8, 14, s, attr)

        stdscr.addstr(10, 0, "PCAP:")
        # PCAP counts: make numeric values use the
        # active/accent color for visibility
        try:
            stdscr.addstr(11, 2, "  Ring        : ")
            stdscr.addstr(11, 21, f"{buff_count:<5}", curses.color_pair(2) | curses.A_BOLD)
            stdscr.addstr(12, 2, "  Backlog     : ")
            stdscr.addstr(12, 21, f"{back_count:<5}", curses.color_pair(3) | curses.A_DIM)
        except Exception:
            stdscr.addstr(11, 2, f"  Ring        : {buff_count:<5}")
            stdscr.addstr(12, 2, f"  Backlog     : {back_count:<5}")

        # Show drive status and destination
        if drive_present:
            # Detect which mount is active
            mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
            active_mount = "drive"
            for candidate in mount_candidates:
                if os.path.ismount(candidate):
                    active_mount = candidate
                    break
            try:
                # Drive connected: label in accent, value bold
                stdscr.addstr(13, 2, "  Drive       : ", curses.color_pair(5))
                stdscr.addstr(13, 17, "CONNECTED", curses.color_pair(2) | curses.A_BOLD)
                stdscr.addstr(14, 2, "  Mount       : ")
                stdscr.addstr(14, 16, f"{active_mount}", curses.color_pair(5))
                stdscr.addstr(15, 2, "  On Drive    : ")
                stdscr.addstr(15, 16, f"{drive_pcap_count} files", curses.color_pair(2))
            except Exception:
                stdscr.addstr(13, 2, "  Drive       : CONNECTED")
                stdscr.addstr(14, 2, f"  Mount       : {active_mount}")
                stdscr.addstr(15, 2, f"  On Drive    : {drive_pcap_count} files")
        else:
            stdscr.addstr(13, 2, "  Drive       : ", curses.color_pair(3))
            stdscr.addstr(13, 17, "not connected")

        # JSON stats: size in accent color
        try:
            stdscr.addstr(14, 0, "JSON:")
            stdscr.addstr(15, 2, "  Captured    : ")
            stdscr.addstr(
                15,
                18,
                f"{human_bytes(j_bytes):<12}",
                curses.color_pair(2) | curses.A_BOLD,
            )
        except Exception:
            stdscr.addstr(14, 0, "JSON:")
            stdscr.addstr(15, 2, f"  Captured    : {human_bytes(j_bytes):<12}")

        # Scout Receiver stats
        recv_stats = get_receiver_stats()
        try:
            stdscr.addstr(16, 0, "SCOUT:")
            if recv_stats:
                total_req = recv_stats.get("total_requests", 0)
                success_rate = recv_stats.get("success_rate", 0)
                data_mb = recv_stats.get("total_data_received_mb", 0)
                sources = recv_stats.get("unique_sources", 0)
                rpm = recv_stats.get("requests_per_minute", 0)
                stdscr.addstr(17, 2, "  Requests    : ")
                stdscr.addstr(17, 18, f"{total_req}", curses.color_pair(2) | curses.A_BOLD)
                stdscr.addstr(17, 26, f" ({success_rate}% ok)", curses.color_pair(5))
                stdscr.addstr(18, 2, "  Data        : ")
                stdscr.addstr(18, 18, f"{data_mb} MB", curses.color_pair(2))
                stdscr.addstr(18, 30, f" ({sources} src, {rpm}/min)", curses.color_pair(5))
            else:
                stdscr.addstr(17, 2, "  Status      : ", curses.color_pair(3))
                stdscr.addstr(17, 18, "unavailable", curses.color_pair(1))
        except Exception:
            stdscr.addstr(16, 0, "SCOUT:")
            if recv_stats:
                stdscr.addstr(
                    17,
                    2,
                    f"  Requests    : {recv_stats.get('total_requests', 0)}",
                )
            else:
                stdscr.addstr(17, 2, "  Status      : unavailable")

        # Controls: make keys accent colored for quick scanning
        try:
            stdscr.addstr(3, left_w + 2, "[1] ")
            stdscr.addstr(3, left_w + 6, "Stop", curses.color_pair(1))
            stdscr.addstr(3, left_w + 12, "   [3] ")
            stdscr.addstr(3, left_w + 18, "Start", curses.color_pair(2) | curses.A_BOLD)

            stdscr.addstr(4, left_w + 2, "[2] ")
            stdscr.addstr(4, left_w + 6, "Mount/Unmount Drive", curses.color_pair(5))

            stdscr.addstr(5, left_w + 2, "[z] ")
            stdscr.addstr(5, left_w + 6, "Zeek Start", curses.color_pair(2))
            stdscr.addstr(5, left_w + 20, "[x] ")
            stdscr.addstr(5, left_w + 24, "Stop", curses.color_pair(1))

            stdscr.addstr(7, left_w + 2, "[c] ")
            stdscr.addstr(7, left_w + 6, "Cap", curses.color_pair(5))
            stdscr.addstr(7, left_w + 12, "[m] ")
            stdscr.addstr(7, left_w + 16, "Mov", curses.color_pair(5))
            stdscr.addstr(7, left_w + 22, "[h] ")
            stdscr.addstr(7, left_w + 26, "Hot", curses.color_pair(5))

            stdscr.addstr(8, left_w + 2, "[r] ")
            stdscr.addstr(8, left_w + 6, "Recv", curses.color_pair(5))
            stdscr.addstr(8, left_w + 12, "[s] ")
            stdscr.addstr(8, left_w + 16, "Status", curses.color_pair(5))

            stdscr.addstr(9, left_w + 2, "[+/-] ")
            stdscr.addstr(9, left_w + 8, "Speed", curses.color_pair(5))

            stdscr.addstr(11, left_w + 2, "[?] ")
            stdscr.addstr(11, left_w + 6, "Help", curses.color_pair(4) | curses.A_BOLD)
            stdscr.addstr(11, left_w + 16, "[q] ")
            stdscr.addstr(11, left_w + 20, "Quit", curses.color_pair(5))
        except Exception:
            stdscr.addstr(3, left_w + 2, "[1] Stop   [3] Start")
            stdscr.addstr(4, left_w + 2, "[2] Mount/Unmount Drive")
            stdscr.addstr(5, left_w + 2, "[z] Zeek Start  [x] Stop")
            stdscr.addstr(7, left_w + 2, "[c] Cap [m] Mov [h] Hot [r] Recv")
            stdscr.addstr(8, left_w + 2, "[s] Status  [+/-] Speed")
            stdscr.addstr(11, left_w + 2, "[?] Help    [q] Quit")

        divider(stdscr, 20, w)
        # Show status message if recent (within 5s);
        # otherwise show last input
        if status_message and (time.time() - status_message_time < 5):
            draw_text(stdscr, 21, 0, w, f"Status: {status_message}")
        else:
            draw_text(stdscr, 21, 0, w, f"Input: {last_key}")
        stdscr.refresh()

        t_end = time.time() + REFRESH
        while time.time() < t_end:
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1
            if ch == -1:
                time.sleep(0.02)
                continue
            if ch in (ord("q"), ord("Q")):
                return
            last_key = chr(ch) if 32 <= ch < 127 else f"[{ch}]"

            if ch == ord("1"):
                act_stop()
            elif ch == ord("2"):
                # Mount/Unmount drive toggle (non-blocking; stay in console)
                status_message = "Processing..."
                stdscr.refresh()
                msg = act_toggle_mount()
                status_message = msg
                status_message_time = time.time()
            elif ch == ord("3"):
                act_start()
            elif ch == ord("?"):
                show_help(stdscr)
            elif ch == ord("+"):
                REFRESH = round(REFRESH + 0.5, 1)
            elif ch == ord("-"):
                REFRESH = round(max(0.5, REFRESH - 0.5), 1)
            elif ch in (ord("c"), ord("C")):
                curses.def_prog_mode()
                curses.endwin()
                svc = shlex.quote(CAPTURE_SERVICE)
                os.system(f"journalctl -u {svc} -n 400 --no-pager | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("m"), ord("M")):
                curses.def_prog_mode()
                curses.endwin()
                svc = shlex.quote(MOVER_SERVICE)
                os.system(f"journalctl -u {svc} -n 400 --no-pager | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("h"), ord("H")):
                curses.def_prog_mode()
                curses.endwin()
                svc = shlex.quote(HOTSWAP_SERVICE)
                os.system(f"journalctl -u {svc} -n 400 --no-pager | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("r"), ord("R")):
                curses.def_prog_mode()
                curses.endwin()
                svc = shlex.quote(RECEIVER_SERVICE)
                os.system(f"journalctl -u {svc} -n 400 --no-pager | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("s"), ord("S")):
                curses.def_prog_mode()
                curses.endwin()
                units = " ".join(
                    [shlex.quote(CAPTURE_SERVICE), shlex.quote(MOVER_SERVICE)]
                    + ([shlex.quote(MOVER_TIMER)] if MOVER_TIMER else [])
                )
                os.system(f"systemctl status {units} --no-pager -l | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("j"), ord("J")):
                curses.def_prog_mode()
                curses.endwin()
                echo = f"ls -lt {shlex.quote(JSON_SPOOL)} | head -n 200"
                os.system(echo + " | sed -n '1,200p' | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("p"), ord("P")):
                curses.def_prog_mode()
                curses.endwin()
                svc = shlex.quote(SHIPPER_SERVICE)
                os.system(f"systemctl status {svc} --no-pager -l | less -SRX")
                curses.reset_prog_mode()
            elif ch in (ord("a"), ord("A")):
                curses.def_prog_mode()
                curses.endwin()
                cat = 'echo "Agent heuristics: (placeholder)\\n- rule1: ...\\n- rule2: ...\\n" | less -SRX'
                os.system(cat)
                curses.reset_prog_mode()
            elif ch == ord("z"):
                curses.def_prog_mode()
                curses.endwin()
                os.system("sudo /usr/local/bin/seer-zeek.sh start; read -n 1 -s -r -p 'Press any key to continue.'")
                curses.reset_prog_mode()
            elif ch == ord("x"):
                curses.def_prog_mode()
                curses.endwin()
                os.system("sudo /usr/local/bin/seer-zeek.sh stop; read -n 1 -s -r -p 'Press any key to continue.'")
                curses.reset_prog_mode()
            # Removed verbose Zeek status viewer to keep UI minimal
            break


def main():
    # One-shot textual status mode
    if getattr(_args, "once", False):
        s = collect_status()
        host = os.uname().nodename
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"SEER STATUS  host={host}  time={now}")
        print(
            f"  CAPTURE : {s['cap_state']}    MOVER: {s['mov_state']}"
            f"   TIMER: {s['tim_state']}   ZEEK: {s['zeek_state']}"
            f"   HOTSWAP: {s['hot_state']}"
        )
        print(f"  RECEIVER: {s['recv_state']}")
        print(f"  RING    : {s['ring_dir']}  count={s['buff_count']}")
        print(f"  BACKLOG : {s['backlog_dir']}  count={s['back_count']}")

        # Show drive status
        exp = s["export"]
        if exp["drive_present"]:
            cfg = read_cfg()
            mount_candidates = cfg.get("export", {}).get("mount_candidates", ["/mnt/seer_external"])
            active_mount = "drive"
            for candidate in mount_candidates:
                if os.path.ismount(candidate):
                    active_mount = candidate
                    break
            print(f"  DRIVE   : CONNECTED at {active_mount}")
            # Count files on drive
            try:
                drive_count = sum(1 for _ in Path(active_mount).rglob("*.pcap*"))
                print(f"  ON DRIVE: {drive_count} files")
            except OSError:
                print("  ON DRIVE: (unable to count)")
        else:
            print("  DRIVE   : not connected")

        j = s["json"]
        print(f"  JSON captured: {human_bytes(j['bytes'])}")

        # Show Scout Receiver stats
        recv = s.get("receiver")
        if recv:
            print("  SCOUT RECEIVER:")
            print(f"    Requests  : {recv.get('total_requests', 0)} total, {recv.get('success_rate', 0)}% success")
            print(f"    Data      : {recv.get('total_data_received_mb', 0)} MB received")
            print(f"    Sources   : {recv.get('unique_sources', 0)} unique")
        return

    # Interactive TUI requires a TTY.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("seer-console: not running in a TTY; interactive console requires a terminal.")
        return
    try:
        curses.wrapper(render)
    except curses.error as e:
        print(f"seer-console: curses error: {e}", file=sys.stderr)
        return


if __name__ == "__main__":
    main()
