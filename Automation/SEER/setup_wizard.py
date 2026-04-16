#!/usr/bin/env python3
"""
Req0 — SEER Setup Wizard
- Prompts for interface, snaplen, rotate interval, etc.
- Creates required directories
- Writes /opt/seer/etc/seer.yml
- Idempotent: backs up existing YAML as seer.yml.bak-YYYYmmdd-HHMMSS
"""

import argparse
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

import yaml

DEFAULTS = {
    "interface": "enp2s0",
    "fanout_id": 42,
    "zeek_workers": 2,
    "refresh_interval": 0.5,
    "buffer_threshold": 4,
    "ring_dir": "/var/seer/pcap_ring",
    "dest_dir": "/opt/seer/var/queue",
    "backlog_dir": "/opt/seer/var/backlog",
    "json_spool": "/var/seer/json_spool",
    "mover_log": "/var/log/seer/mover.log",
    "capture": {
        "snaplen": 128,
        "rotate_seconds": 20,
        "disk_soft_pct": 80,
        "disk_hard_pct": 90,
    },
    "export": {
        "mount_candidates": [
            "/mnt/seer_external",
            "/mnt/SEER_EXT",
            "/media/seer_external",
        ],
        "min_free_pct": 2,
        "poll_interval": 2,
    },
    # How long (seconds) to wait for link at boot before starting capture
    "wait_link_timeout": 60,
    # Scout Receiver configuration (HTTP server for SCOUT Agent data)
    "scout_receiver": {
        "enabled": True,
        "server": {
            "host": "0.0.0.0",
            "port": 8080,
            "cors_enabled": True,
            "max_request_size_mb": 50,
        },
        "storage": {
            "data_dir": "/var/seer/scout_data",
            "max_file_size_mb": 100,
            "rotate_files": True,
            "retention_days": 30,
            "organize_by_date": True,
        },
        "validation": {
            "enforce_schema": True,
            "verify_checksums": True,
            "max_data_size_mb": 50,
            "strict_mode": False,
        },
        "heartbeat": {
            "enabled": True,
            "interval_seconds": 30,
            "response_delay_ms": 0,
        },
        "logging": {
            "level": "INFO",
            "format": "structured",
            "file": "/var/log/seer/scout_receiver.log",
            "max_size_mb": 50,
            "backup_count": 5,
        },
        "web_interface": {
            "enabled": True,
            "static_path": "/opt/seer/www/scout_dashboard",
        },
    },
}

YAML_PATH = Path("/opt/seer/etc/seer.yml")
REQUIRED_DIRS = [
    "/opt/seer/bin",
    "/opt/seer/etc",
    "/opt/seer/var/queue",
    "/opt/seer/var/backlog",
    "/var/seer/pcap_ring",
    "/var/seer/json_spool",
    "/var/seer/scout_data",
    "/var/log/seer",
    "/opt/seer/www/scout_dashboard",
]


def prompt_str(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def prompt_int(label: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    while True:
        s = input(f"{label} [{default}]: ").strip() or str(default)
        try:
            n = int(s)
            if lo is not None and n < lo:
                raise ValueError
            if hi is not None and n > hi:
                raise ValueError
            return n
        except ValueError:
            rng = []
            if lo is not None:
                rng.append(f">={lo}")
            if hi is not None:
                rng.append(f"<={hi}")
            print("  Enter an integer", " and ".join(rng))


def prompt_float(label: str, default: float, lo: float | None = None, hi: float | None = None) -> float:
    while True:
        s = input(f"{label} [{default}]: ").strip() or str(default)
        try:
            n = float(s)
            if lo is not None and n < lo:
                raise ValueError
            if hi is not None and n > hi:
                raise ValueError
            return n
        except ValueError:
            print("  Enter a number.")


def prompt_bool(label: str, default: bool) -> bool:
    """Prompt for a yes/no boolean value."""
    default_str = "Y/n" if default else "y/N"
    while True:
        s = input(f"{label} [{default_str}]: ").strip().lower()
        if not s:
            return default
        if s in ("y", "yes", "true", "1"):
            return True
        if s in ("n", "no", "false", "0"):
            return False
        print("  Enter y/yes or n/no.")


def iface_exists(name: str) -> bool:
    return name != "lo" and Path(f"/sys/class/net/{name}").exists()


def ensure_seer_user() -> None:
    os.system("getent group seer >/dev/null 2>&1 || sudo groupadd -r seer")
    os.system("id -u seer >/dev/null 2>&1 || sudo useradd -r -g seer -s /usr/sbin/nologin seer")


def ensure_dirs() -> None:
    for d in REQUIRED_DIRS:
        Path(d).mkdir(parents=True, exist_ok=True)
    os.system("sudo chown -R seer:seer /opt/seer /var/seer /var/log/seer >/dev/null 2>&1 || true")
    os.system(
        "sudo chmod 0755 /opt/seer /opt/seer/bin /opt/seer/etc /opt/seer/var "
        "/var/seer /var/seer/* /var/log/seer >/dev/null 2>&1 || true"
    )


def backup_yaml() -> None:
    if YAML_PATH.exists():
        ts = time.strftime("%Y%m%d-%H%M%S")
        bak = YAML_PATH.with_name(f"seer.yml.bak-{ts}")
        shutil.copy2(YAML_PATH, bak)
        print(f"Backed up existing YAML to {bak}")


def write_yaml(cfg: dict) -> None:
    YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(YAML_PATH, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    os.system("sudo chown seer:seer /opt/seer/etc/seer.yml")
    os.system("sudo chmod 0644 /opt/seer/etc/seer.yml")
    print(f"Wrote {YAML_PATH}")


def install_wait_helper(iface: str) -> None:
    """Install the wait-for-link helper script and a
    systemd drop-in so capture waits for link at boot.
    This is best-effort and may require sudo.
    """
    # default timeout (seconds)
    timeout = 60
    try:
        src = Path(__file__).parents[2] / "bin" / "seer-wait-link.sh"
        dst = Path("/usr/local/bin/seer-wait-link.sh")
        drop_dir = "/etc/systemd/system/seer-capture@.service.d"
        drop_file = f"{drop_dir}/wait-link.conf"

        if src.exists():
            print(f"Installing wait helper to {dst}")
            # copy with sudo
            os.system(f"sudo install -m 0755 {shlex.quote(str(src))} {shlex.quote(str(dst))} || true")
            os.system(f"sudo chown root:root {shlex.quote(str(dst))} || true")
        else:
            print("Warning: wait helper source not found; skipping installation of helper script.")

        # If YAML exists, try to read configured timeout
        try:
            if YAML_PATH.exists():
                cfg = yaml.safe_load(open(YAML_PATH)) or {}
                timeout = int(cfg.get("wait_link_timeout", timeout))
        except Exception:
            pass

        # write drop-in to call the helper before the service starts
        content = (
            f"[Unit]\nDescription=Wait for link before starting capture\n"
            f"Before=seer-capture@%i.service\n\n[Service]\n"
            f"ExecStartPre=/usr/local/bin/seer-wait-link.sh %i {int(timeout)}\n"
        )
        # Ensure drop-in directory exists and write the drop-in via sudo
        os.system(f"sudo mkdir -p {shlex.quote(drop_dir)} || true")
        cmd = f"echo {shlex.quote(content)} | sudo tee {shlex.quote(drop_file)} >/dev/null"
        os.system(cmd)

        # reload systemd so the drop-in is recognized
        os.system("sudo systemctl daemon-reload || true")
        # enable and restart the capture service for this iface
        os.system(f"sudo systemctl enable --now seer-capture@{iface}.service || true")
    except Exception as e:
        print(f"Failed to install wait helper: {e}")


def configure_monitor_iface(iface: str) -> None:
    """Bring interface up, enable promiscuous mode, and disable common offloads.
    Best-effort with sudo; prints a short status line.
    """
    if not iface or iface == "lo" or not iface_exists(iface):
        print(f"Skipping NIC setup: invalid interface '{iface}'.")
        return
    print(f"Configuring monitor port: {iface} (UP, PROMISC on, offloads off)")
    os.system(f"sudo ip link set dev {iface} up >/dev/null 2>&1")
    os.system(f"sudo ip link set dev {iface} promisc on >/dev/null 2>&1")
    # ethtool may not exist; that's fine
    if shutil.which("ethtool"):
        os.system(f"sudo ethtool -K {iface} gro off lro off tso off gso off >/dev/null 2>&1 || true")
    # Show a brief confirmation line
    os.system(f"ip -d link show {iface} | sed -n '1p' || true")


def main(non_interactive: bool = False) -> None:
    print("== SEER Setup Wizard ==")
    cfg = DEFAULTS.copy()

    if non_interactive:
        # Use defaults but validate interface exists;
        # fallback to first non-loopback
        default_iface = cfg["interface"]
        if iface_exists(default_iface):
            cfg["interface"] = default_iface
        else:
            # try to pick one from /sys/class/net
            for p in Path("/sys/class/net").iterdir():
                if p.name != "lo" and iface_exists(p.name):
                    cfg["interface"] = p.name
                    break
        # Non-interactive: write defaults and exit early
        ensure_seer_user()
        ensure_dirs()
        backup_yaml()
        write_yaml(cfg)
        # Apply monitor-port configuration immediately (best-effort)
        try:
            configure_monitor_iface(cfg["interface"])
        except Exception:
            print(
                "Warning: NIC monitor configuration step failed (non-fatal). You can configure later with ip/ethtool."
            )
        # Install wait-for-link helper and drop-in so
        # capture waits for link at boot
        try:
            install_wait_helper(cfg["interface"])
        except Exception:
            print("Warning: failed to install wait-for-link helper (non-fatal)")
        print("Done. Next: install/start capture and mover services.")
        return
    else:
        # Interface
        while True:
            iface = prompt_str("Network interface", cfg["interface"])
            if iface_exists(iface):
                cfg["interface"] = iface
                break
            print("  Interface not found. (Tip: run `ip link` to list names.)")

    # Capture params
    cfg["capture"]["snaplen"] = prompt_int(
        "tcpdump snaplen (bytes)",
        cfg["capture"]["snaplen"],
        64,
        65535,
    )
    cfg["capture"]["rotate_seconds"] = prompt_int(
        "Rotation interval (seconds)",
        cfg["capture"]["rotate_seconds"],
        5,
        300,
    )

    # Zeek & fanout (for later requirements)
    cfg["zeek_workers"] = prompt_int(
        "Zeek workers",
        cfg["zeek_workers"],
        1,
        os.cpu_count() or 1,
    )
    cfg["fanout_id"] = prompt_int("AF_PACKET fanout ID", cfg["fanout_id"], 1, 65535)

    # UI/mover
    cfg["refresh_interval"] = prompt_float(
        "UI refresh interval (seconds)",
        cfg["refresh_interval"],
        0.1,
        5.0,
    )
    cfg["buffer_threshold"] = prompt_int(
        "Mover threshold (# files before moving)",
        cfg["buffer_threshold"],
        2,
        999,
    )

    # Paths
    for k in ["ring_dir", "dest_dir", "backlog_dir", "json_spool", "mover_log"]:
        cfg[k] = prompt_str(f"{k} path", cfg[k])

    # Disk guardrails
    soft = prompt_int("Disk soft limit %", cfg["capture"]["disk_soft_pct"], 1, 99)
    hard = prompt_int("Disk hard limit %", cfg["capture"]["disk_hard_pct"], 1, 99)
    if soft >= hard:
        print("  soft% must be < hard%; adjusting soft = hard-1.")
        soft = hard - 1
    cfg["capture"]["disk_soft_pct"] = soft
    cfg["capture"]["disk_hard_pct"] = hard

    # Scout Receiver configuration (HTTP server for SCOUT Agent data)
    print("\n== Scout Receiver Configuration ==")
    print("The Scout Receiver accepts data from SCOUT Agents running on Windows endpoints.")

    cfg["scout_receiver"]["enabled"] = prompt_bool("Enable Scout Receiver", cfg["scout_receiver"]["enabled"])

    if cfg["scout_receiver"]["enabled"]:
        cfg["scout_receiver"]["server"]["host"] = prompt_str(
            "Scout Receiver listen address (0.0.0.0 for all interfaces)",
            cfg["scout_receiver"]["server"]["host"],
        )
        cfg["scout_receiver"]["server"]["port"] = prompt_int(
            "Scout Receiver HTTP port",
            cfg["scout_receiver"]["server"]["port"],
            1024,
            65535,
        )
        cfg["scout_receiver"]["storage"]["data_dir"] = prompt_str(
            "Scout data storage directory",
            cfg["scout_receiver"]["storage"]["data_dir"],
        )
        cfg["scout_receiver"]["storage"]["retention_days"] = prompt_int(
            "Data retention (days)",
            cfg["scout_receiver"]["storage"]["retention_days"],
            1,
            365,
        )
        cfg["scout_receiver"]["validation"]["verify_checksums"] = prompt_bool(
            "Verify data checksums",
            cfg["scout_receiver"]["validation"]["verify_checksums"],
        )
        cfg["scout_receiver"]["logging"]["level"] = prompt_str(
            "Log level (DEBUG/INFO/WARNING/ERROR)",
            cfg["scout_receiver"]["logging"]["level"],
        ).upper()

    # Do work
    ensure_seer_user()
    ensure_dirs()
    backup_yaml()
    write_yaml(cfg)
    # Apply monitor-port configuration immediately (best-effort)
    try:
        configure_monitor_iface(cfg["interface"])
    except Exception:
        print("Warning: NIC monitor configuration step failed (non-fatal). You can configure later with ip/ethtool.")
    # Install wait-for-link helper and drop-in so
    # capture waits for link at boot
    try:
        install_wait_helper(cfg["interface"])
    except Exception:
        print("Warning: failed to install wait-for-link helper (non-fatal)")
    print("Done. Next: install/start capture and mover services.")


def cli_main():
    p = argparse.ArgumentParser(description="SEER setup wizard (interactive)")
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Use defaults and be non-interactive",
    )
    args = p.parse_args()
    try:
        main(non_interactive=args.yes)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)


if __name__ == "__main__":
    cli_main()
