"""Tests for seer_uninstall.py.

Verifies argument parsing, confirmation handling, sudo re-exec, service
stop/disable sequencing, process kill escalation, binary removal, purge
behavior, and export drive handling.
"""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.abspath("Automation/bin"))
import seer_uninstall as su

# -------------------------
# Helpers
# -------------------------


def mock_run_success(*args, **kwargs) -> object:
    """Return a mock CompletedProcess with returncode=0."""

    class _Result:
        returncode = 0
        stdout = ""

    return _Result()


# -------------------------
# Tests
# -------------------------


def test_main_help_flag_prints_usage_and_returns_0():
    """Verify --help prints usage text and exits with code 0."""
    with patch("builtins.print") as p:
        rc = su.main(["prog", "--help"])

    assert rc == 0
    p.assert_any_call(
        "SEER uninstall\n"
        "\nUsage: prog [--purge] [--yes]\n"
        "\n  --purge   Also delete config (/opt/seer) and data"
        " (/var/seer, /var/lib/tcpdump/pcap_ring)"
        "\n  --yes     Do not prompt for confirmation"
    )


def test_main_unknown_arg_prints_message_and_returns_2():
    """Verify unknown argument prints an error message and exits with code 2."""
    with patch("builtins.print") as p:
        rc = su.main(["prog", "--badflag"])

    assert rc == 2
    p.assert_any_call("Unknown arg: --badflag")


def test_main_user_declines_confirmation_returns_1():
    """Verify exit code 1 when user answers 'N' at the confirmation prompt."""
    with patch("seer_uninstall.confirm", return_value=False):
        with patch("os.geteuid", return_value=0):
            rc = su.main(["prog"])

    assert rc == 1


def test_main_non_root_reexecs_with_sudo():
    """Verify the script re-execs itself under sudo when not running as root."""
    with patch("os.geteuid", return_value=1000):
        with patch("seer_uninstall.os.execvp", side_effect=SystemExit(0)) as execvp:
            try:
                su.main(["prog"])
            except SystemExit:
                pass

    execvp.assert_called_once()
    assert "sudo" in execvp.call_args[0][0]


def test_main_no_purge_completes_successfully_returns_0():
    """Verify full uninstall flow without purge completes and returns 0."""
    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success):
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                        with patch("seer_uninstall.is_process_running_exact", return_value=False):
                            with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                                with patch("glob.glob", return_value=[]):
                                    with patch("time.sleep"):
                                        with patch("builtins.print") as p:
                                            rc = su.main(["prog"])

    assert rc == 0
    p.assert_any_call("You can reinstall with:")


def test_main_purge_flag_calls_remove_dir_and_returns_0():
    """Verify --purge path calls remove_dir_if_present for key data directories."""
    removed_dirs: list = []

    def remove_dir_mock(path: str) -> None:
        removed_dirs.append(path)

    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success):
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                        with patch("seer_uninstall.is_process_running_exact", return_value=False):
                            with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                                with patch("seer_uninstall.load_mount_candidates", return_value=[]):
                                    with patch(
                                        "seer_uninstall.remove_dir_if_present",
                                        side_effect=remove_dir_mock,
                                    ):
                                        with patch("glob.glob", return_value=[]):
                                            with patch("time.sleep"):
                                                with patch("builtins.print") as p:
                                                    rc = su.main(["prog", "--purge"])

    assert rc == 0
    p.assert_any_call("  \u2714 config/data purged")
    assert "/opt/seer" in removed_dirs
    assert "/var/seer" in removed_dirs


def test_main_lingering_processes_receive_sigkill_escalation():
    """Verify SIGKILL is sent when processes remain after graceful kill attempts."""

    def proc_mock(*args, **kwargs) -> bool:
        return True  # Pretend processes are always still running.

    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success) as run_mock:
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                        with patch("seer_uninstall.is_process_running_exact", side_effect=proc_mock):
                            with patch("seer_uninstall.is_process_running_pattern", return_value=True):
                                with patch("glob.glob", return_value=[]):
                                    with patch("time.sleep"):
                                        su.main(["prog"])

    assert any("-9" in str(call.args[0]) for call in run_mock.call_args_list)


def test_main_unmounted_export_drive_warns_to_stderr(capsys: object) -> None:
    """Verify a warning is written to stderr when the export drive is not mounted."""

    def run_mock(cmd, *args, **kwargs) -> object:
        class _R:
            returncode = 1
            stdout = ""

        return _R()

    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=run_mock):
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                        with patch("seer_uninstall.is_process_running_exact", return_value=False):
                            with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                                with patch(
                                    "seer_uninstall.load_mount_candidates",
                                    return_value=["/mnt/test"],
                                ):
                                    with patch("seer_uninstall.remove_dir_if_present"):
                                        with patch("glob.glob", return_value=[]):
                                            with patch("time.sleep"):
                                                su.main(["prog", "--purge"])

    captured = capsys.readouterr()
    assert "not mounted; skipping export purge" in captured.err


def test_main_binary_removal_calls_rm_for_installed_paths():
    """Verify rm -f is invoked for known installed binary paths."""
    calls: list = []

    def run_mock(cmd, *args, **kwargs) -> object:
        calls.append(cmd)
        return mock_run_success()

    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=run_mock):
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                        with patch("seer_uninstall.is_process_running_exact", return_value=False):
                            with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                                with patch("glob.glob", return_value=[]):
                                    with patch("time.sleep"):
                                        su.main(["prog"])

    assert any("/usr/local/bin/seer-capture.sh" in str(c) for c in calls)


def test_main_yes_flag_skips_confirmation_prompt():
    """Verify --yes bypasses the interactive confirmation prompt."""
    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success):
            with patch("seer_uninstall.sc", side_effect=mock_run_success):
                with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                    with patch("seer_uninstall.is_process_running_exact", return_value=False):
                        with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                            with patch("glob.glob", return_value=[]):
                                with patch("time.sleep"):
                                    with patch("builtins.input") as mock_input:
                                        rc = su.main(["prog", "--yes"])

    assert rc == 0
    mock_input.assert_not_called()


def test_main_short_y_flag_skips_confirmation_prompt():
    """Verify -y is accepted as an alias for --yes."""
    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success):
            with patch("seer_uninstall.sc", side_effect=mock_run_success):
                with patch("seer_uninstall.list_loaded_template_units", return_value=[]):
                    with patch("seer_uninstall.is_process_running_exact", return_value=False):
                        with patch("seer_uninstall.is_process_running_pattern", return_value=False):
                            with patch("glob.glob", return_value=[]):
                                with patch("time.sleep"):
                                    rc = su.main(["prog", "-y"])

    assert rc == 0


def test_main_discovered_template_units_are_stopped():
    """Verify dynamically discovered templated units are passed to stop_units."""
    stopped: list = []

    def stop_mock(units) -> None:
        stopped.extend(units)

    with patch("os.geteuid", return_value=0):
        with patch("seer_uninstall.confirm", return_value=True):
            with patch("seer_uninstall.run_best_effort", side_effect=mock_run_success):
                with patch("seer_uninstall.sc", side_effect=mock_run_success):
                    with patch(
                        "seer_uninstall.list_loaded_template_units",
                        side_effect=lambda p: (
                            ["seer-capture@eth0.service"] if "capture" in p else ["seer-zeek@eth0.service"]
                        ),
                    ):
                        with patch("seer_uninstall.stop_units", side_effect=stop_mock):
                            with patch("seer_uninstall.disable_units"):
                                with patch(
                                    "seer_uninstall.is_process_running_exact",
                                    return_value=False,
                                ):
                                    with patch(
                                        "seer_uninstall.is_process_running_pattern",
                                        return_value=False,
                                    ):
                                        with patch("glob.glob", return_value=[]):
                                            with patch("time.sleep"):
                                                su.main(["prog"])

    assert "seer-capture@eth0.service" in stopped
    assert "seer-zeek@eth0.service" in stopped
