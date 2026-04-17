#!/usr/bin/env python3
"""Uninstall SEER services, units, binaries, and optional data.

This script stops and disables SEER-related systemd units, removes installed
unit files and binaries, and optionally purges configuration, local data, and
SEER-created export-drive contents.
"""

import glob
import os
import subprocess
import sys
import time
from typing import Any, Iterable, List


def usage(argv0: str) -> None:
    """Print command usage information.

    Args:
        argv0: Program name to display in the usage line.

    Returns:
        None
    """
    print(
        f"SEER uninstall\n"
        f"\nUsage: {argv0} [--purge] [--yes]\n"
        f"\n  --purge   Also delete config (/opt/seer) and data"
        f" (/var/seer, /var/lib/tcpdump/pcap_ring)"
        f"\n  --yes     Do not prompt for confirmation"
    )


def say(message: str) -> None:
    """Print a bold status line.

    Args:
        message: Message text to display.

    Returns:
        None
    """
    print(f"\033[1m{message}\033[0m")


def ok(message: str) -> None:
    """Print a success line.

    Args:
        message: Message text to display.

    Returns:
        None
    """
    print(f"  \u2714 {message}")


def warn(message: str) -> None:
    """Print a warning line to stderr.

    Args:
        message: Message text to display.

    Returns:
        None
    """
    print(f"  ! {message}", file=sys.stderr)


def run_best_effort(
    cmd: List[str],
    *,
    stdout: Any = None,
    stderr: Any = None,
    text: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command without raising exceptions.

    Mirrors shell commands wrapped with `|| true` or error-redirected to
    suppress noise. Returns a synthetic nonzero result instead of raising.

    Args:
        cmd: Command and arguments to execute.
        stdout: Optional stdout target passed to subprocess.run.
        stderr: Optional stderr target passed to subprocess.run.
        text: Whether to request text output from subprocess.run.

    Returns:
        CompletedProcess with the command's return code.
    """
    try:
        return subprocess.run(
            cmd,
            check=False,
            stdout=stdout,
            stderr=stderr,
            text=text,
        )
    except Exception:  # Intentional isolation point
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="" if text else None,
            stderr="" if text else None,
        )


def sc(*args: str) -> subprocess.CompletedProcess:
    """Run a systemctl command without interactive password prompts.

    Args:
        *args: Arguments to pass after `systemctl --no-ask-password`.

    Returns:
        CompletedProcess for the systemctl invocation.
    """
    return run_best_effort(
        ["systemctl", "--no-ask-password", *args],
        stderr=subprocess.DEVNULL,
    )


def stop_units(units: Iterable[str]) -> None:
    """Stop systemd units with bounded timeouts and signal fallbacks.

    Args:
        units: Unit names to stop.

    Returns:
        None
    """
    unit_list = list(units)
    if not unit_list:
        return

    for unit in unit_list:
        sc("kill", "-s", "INT", unit)
        sc("stop", "--timeout=10s", unit)
        sc("kill", "-s", "KILL", unit)
        sc("stop", "--timeout=3s", unit)


def disable_units(units: Iterable[str]) -> None:
    """Disable units and clear failed state.

    Args:
        units: Unit names to disable.

    Returns:
        None
    """
    unit_list = list(units)
    if not unit_list:
        return

    for unit in unit_list:
        sc("disable", unit)
        sc("reset-failed", unit)


def confirm(assume_yes: bool) -> bool:
    """Prompt for uninstall confirmation unless assume_yes is set.

    Args:
        assume_yes: When True, skip the prompt and return True immediately.

    Returns:
        True if the uninstall should proceed, otherwise False.
    """
    if assume_yes:
        return True

    answer = input("Proceed? [y/N] ")
    return answer in ("y", "Y")


def list_loaded_template_units(pattern: str) -> List[str]:
    """Return loaded unit names matching a systemd glob pattern.

    Args:
        pattern: Unit-name pattern to pass to `systemctl list-units`.

    Returns:
        List of matching unit names extracted from the first column.
    """
    result = run_best_effort(
        [
            "systemctl",
            "--no-ask-password",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--plain",
            pattern,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    lines = result.stdout.splitlines() if isinstance(result.stdout, str) else []
    units: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        units.append(stripped.split()[0])
    return units


def is_process_running_exact(name: str) -> bool:
    """Check whether a process with an exact name is running.

    Args:
        name: Exact process name to test with `pgrep -x`.

    Returns:
        True if a matching process is present, otherwise False.
    """
    result = run_best_effort(
        ["pgrep", "-x", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def is_process_running_pattern(pattern: str) -> bool:
    """Check whether a process matching a pattern is running.

    Args:
        pattern: Pattern to test with `pgrep -f`.

    Returns:
        True if a matching process is present, otherwise False.
    """
    result = run_best_effort(
        ["pgrep", "-f", pattern],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def remove_file_if_present(path: str) -> None:
    """Remove a file if it exists, ignoring errors.

    Args:
        path: File path to remove.

    Returns:
        None
    """
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception:  # Intentional isolation point — best-effort removal.
        pass


def remove_dir_if_present(path: str) -> None:
    """Remove a directory tree if it exists, using rm -rf for reliability.

    Uses subprocess rm -rf to handle symlinks and special files correctly

    Args:
        path: Directory path to remove.

    Returns:
        None
    """
    if not os.path.isdir(path):
        return
    run_best_effort(["rm", "-rf", path])


def load_mount_candidates() -> List[str]:
    """Load export-drive mount candidates from the SEER YAML config.

    Returns:
        List of mount paths, or the default mount if config is missing or unreadable.
    """
    config_path = "/opt/seer/etc/seer.yml"
    default_mounts = ["/mnt/seer_external"]

    if not os.path.isfile(config_path):
        return default_mounts

    try:
        import yaml  # noqa: PLC0415

        with open(config_path, "r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}

        export_cfg = config.get("export", {}) or {}
        mounts = export_cfg.get("mount_candidates", default_mounts)

        if isinstance(mounts, str):
            return [mounts]
        if isinstance(mounts, list):
            return list(mounts)
        return default_mounts
    except Exception:  # Intentional isolation point — config is optional.
        return default_mounts


def purge_export_drive() -> None:
    """Remove SEER-created export content from mounted export drives.

    Returns:
        None
    """
    mounts = load_mount_candidates()

    for mount_path in mounts:
        if not mount_path:
            continue

        mounted = (
            run_best_effort(
                ["mountpoint", "-q", "--", mount_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )

        if mounted:
            say(
                f"   - Export drive mounted at {mount_path}:"
                f" purging SEER export files (pcap/)"
            )

            pcap_dir = os.path.join(mount_path, "pcap")
            if os.path.isdir(pcap_dir):
                run_best_effort(["rm", "-rf", "--one-file-system", pcap_dir])
                ok(f"removed {mount_path}/pcap")

            for filename in ("MANIFEST.txt", "TRANSFER.LOG"):
                remove_file_if_present(os.path.join(mount_path, filename))

            try:
                for entry in os.listdir(mount_path):
                    entry_path = os.path.join(mount_path, entry)
                    if (
                        os.path.isdir(entry_path)
                        and entry.startswith("pcap")
                        and not os.listdir(entry_path)
                    ):
                        try:
                            os.rmdir(entry_path)
                        except (
                            Exception
                        ):  # Intentional — skip dirs we can't remove.
                            pass
            except (
                Exception
            ):  # Intentional isolation point — mount may disappear.
                pass
        else:
            warn(f"   - {mount_path} not mounted; skipping export purge")


def main(argv: List[str]) -> int:
    """Run the uninstall workflow.

    Args:
        argv: Raw command-line arguments.

    Returns:
        Process exit code.
    """
    purge = False
    assume_yes = False

    args = list(argv[1:])
    while args:
        current = args.pop(0)

        if current == "--purge":
            purge = True
        elif current in ("--yes", "-y"):
            assume_yes = True
        elif current in ("-h", "--help"):
            usage(argv[0])
            return 0
        else:
            print(f"Unknown arg: {current}")
            usage(argv[0])
            return 2

    euid = int(os.environ.get("EUID", os.geteuid()))
    if euid != 0:
        os.execvp("sudo", ["sudo", "-E", "python3", argv[0], *argv[1:]])

    say("SEER uninstall plan:")
    print(
        "  - Stop & disable: seer-capture@*.service, seer-move-oldest.service, "
        "seer-move-oldest.timer, seer-zeek@*.service, seer-hotswap.service"
    )
    print(
        "  - Remove units   : /etc/systemd/system/seer-capture@.service, "
        "seer-move-oldest.{service,timer},"
        " seer-zeek@.service, seer-hotswap.service"
    )
    print(
        "  - Remove binaries: /usr/local/bin/seer-capture.sh, "
        "/usr/local/bin/seer_console.py, /usr/local/bin/seer-console, "
        "/usr/local/bin/seer-zeek.sh, /usr/local/bin/seer_hotswap.py"
    )

    if purge:
        print(
            "  - PURGE config   : /opt/seer"
            " (incl. /opt/seer/etc/seer.yml backups)"
        )
        print(
            "  - PURGE data     : /var/seer and"
            " /var/lib/tcpdump/pcap_ring (PCAPs WILL BE DELETED)"
        )
        print(
            "  - PURGE export   : if an export drive is mounted at configured"
            " mount point(s), delete SEER 'pcap/' contents on that drive"
        )
    else:
        print("  - Keep config    : /opt/seer")
        print("  - Keep data      : /var/seer and /var/lib/tcpdump/pcap_ring")

    if not confirm(assume_yes):
        warn("Aborted.")
        return 1

    say("1) Stop & disable services/timer")

    capture_units = list_loaded_template_units("seer-capture@*.service")
    zeek_units = list_loaded_template_units("seer-zeek@*.service")

    stop_units(capture_units)
    stop_units(zeek_units)
    stop_units(
        [
            "seer-move-oldest.timer",
            "seer-move-oldest.service",
            "seer-hotswap.service",
        ]
    )
    disable_units(capture_units)
    disable_units(zeek_units)
    disable_units(
        [
            "seer-move-oldest.timer",
            "seer-move-oldest.service",
            "seer-hotswap.service",
        ]
    )
    ok("services/timer stopped & disabled (where present)")

    say("1b) Ensure capture/zeek/hotswap processes are not running")

    stop_units([*capture_units, *zeek_units, "seer-hotswap.service"])

    run_best_effort(["pkill", "-x", "tcpdump"], stderr=subprocess.DEVNULL)
    run_best_effort(["pkill", "-x", "zeek"], stderr=subprocess.DEVNULL)
    run_best_effort(
        ["pkill", "-f", "seer_hotswap.py"], stderr=subprocess.DEVNULL
    )

    for _ in (1, 2, 3, 4, 5):
        time.sleep(1)
        if (
            not is_process_running_exact("tcpdump")
            and not is_process_running_exact("zeek")
            and not is_process_running_pattern("seer_hotswap.py")
        ):
            break

    if is_process_running_exact("tcpdump"):
        run_best_effort(
            ["pkill", "-9", "-x", "tcpdump"], stderr=subprocess.DEVNULL
        )
    if is_process_running_exact("zeek"):
        run_best_effort(
            ["pkill", "-9", "-x", "zeek"], stderr=subprocess.DEVNULL
        )
    if is_process_running_pattern("seer_hotswap.py"):
        run_best_effort(
            ["pkill", "-9", "-f", "seer_hotswap.py"], stderr=subprocess.DEVNULL
        )

    for path in glob.glob("/run/zeek-*.pid"):
        remove_file_if_present(path)
    for path in glob.glob("/run/zeek-*.lock"):
        remove_file_if_present(path)

    ok("lingering processes terminated")

    say("2) Remove systemd unit files")
    run_best_effort(
        [
            "rm",
            "-f",
            "/etc/systemd/system/seer-capture@.service",
            "/etc/systemd/system/seer-move-oldest.service",
            "/etc/systemd/system/seer-move-oldest.timer",
            "/etc/systemd/system/seer-move-oldest.path",
            "/etc/systemd/system/seer-zeek@.service",
            "/etc/systemd/system/seer-hotswap.service",
        ]
    )
    sc("daemon-reload")
    ok("systemd units removed and daemon reloaded")

    say("3) Remove installed binaries")
    run_best_effort(
        [
            "rm",
            "-f",
            "/usr/local/bin/seer-capture.sh",
            "/usr/local/bin/seer_console.py",
            "/usr/local/bin/seer-console",
            "/usr/local/bin/seer-zeek.sh",
            "/usr/local/bin/seer-move-oldest.py",
            "/usr/local/bin/seer_hotswap.py",
            "/usr/local/bin/seer",
            "/usr/local/bin/seer-toggle-drive",
            "/usr/local/bin/seer-verify-install.sh",
        ]
    )
    if os.path.isfile("/usr/bin/seer-capture.sh"):
        run_best_effort(["rm", "-f", "/usr/bin/seer-capture.sh"])
    if os.path.isfile("/usr/bin/seer-console"):
        run_best_effort(["rm", "-f", "/usr/bin/seer-console"])
    ok("binaries removed")

    if purge:
        say("4) PURGE config and data")
        purge_export_drive()

        remove_dir_if_present("/opt/seer")
        remove_dir_if_present("/var/seer")
        remove_dir_if_present("/var/log/seer")
        remove_dir_if_present("/var/log/zeek")
        remove_dir_if_present("/var/lib/tcpdump/pcap_ring")

        ok("config/data purged")
    else:
        say("4) Skipping purge (config/data kept)")

    say("5) Done")
    print("You can reinstall with:")
    print("  sudo -E Automation/SEER/setup_wizard.py")
    print("  Automation/install.sh")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
