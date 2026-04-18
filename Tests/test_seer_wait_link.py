"""Tests for seer_wait_link.py.

Verifies link detection logic, timeout handling, environment variable support,
stderr output, promisc mode activation, and best-effort failure tolerance.
"""

import os
import sys
from unittest.mock import mock_open, patch

sys.path.append(os.path.abspath("Automation/bin"))
import seer_wait_link as swl

# -------------------------
# Helpers
# -------------------------


def run_success(stdout: str = "") -> object:
    """Return a mock CompletedProcess with returncode=0."""

    class _Result:
        returncode = 0

        def __init__(self) -> None:
            self.stdout = stdout

    return _Result()


def run_fail() -> object:
    """Return a mock CompletedProcess with returncode=1."""

    class _Result:
        returncode = 1
        stdout = ""

    return _Result()


# -------------------------
# Tests
# -------------------------


def test_main_missing_iface_prints_usage_to_stderr_and_returns_2():
    """Verify missing interface prints usage to stderr and exits with code 2."""
    with patch("builtins.print") as p:
        rc = swl.main(["prog"])

    assert rc == 2
    p.assert_called_with("seer-wait-link: missing iface", file=sys.stderr)


def test_main_carrier_up_returns_0():
    """Verify exit code 0 when sysfs carrier file reports link up."""
    with patch("builtins.open", mock_open(read_data="1")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep"):
                rc = swl.main(["prog", "eth0"])

    assert rc == 0


def test_main_carrier_up_message_goes_to_stderr(capsys: object) -> None:
    """Verify carrier detection status message is written to stderr."""
    with patch("builtins.open", mock_open(read_data="1")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep"):
                swl.main(["prog", "eth0"])

    captured = capsys.readouterr()
    assert "carrier detected" in captured.err


def test_main_lower_up_fallback_returns_0():
    """Verify exit code 0 when LOWER_UP is detected in ip -d link show output."""

    def run_mock(cmd: list) -> object:
        if "show" in cmd:
            return run_success("LOWER_UP")
        return run_success()

    with patch("builtins.open", side_effect=Exception):
        with patch("seer_wait_link.run_best_effort", side_effect=run_mock):
            with patch("time.sleep"):
                rc = swl.main(["prog", "eth0"])

    assert rc == 0


def test_main_lower_up_message_goes_to_stderr(capsys: object) -> None:
    """Verify LOWER_UP detection status message is written to stderr."""

    def run_mock(cmd: list) -> object:
        if "show" in cmd:
            return run_success("LOWER_UP")
        return run_success()

    with patch("builtins.open", side_effect=Exception):
        with patch("seer_wait_link.run_best_effort", side_effect=run_mock):
            with patch("time.sleep"):
                swl.main(["prog", "eth0"])

    captured = capsys.readouterr()
    assert "LOWER_UP" in captured.err


def test_main_timeout_returns_0():
    """Verify exit code 0 on timeout — script never fails the caller."""
    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep"):
                rc = swl.main(["prog", "eth0", "2"])

    assert rc == 0


def test_main_timeout_message_includes_value_and_goes_to_stderr(
    capsys: object,
) -> None:
    """Verify timeout message is on stderr and includes the configured
    timeout value."""
    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep"):
                swl.main(["prog", "eth0", "2"])

    captured = capsys.readouterr()
    assert "timed out" in captured.err
    assert "2s" in captured.err


def test_main_default_timeout_is_60_seconds():
    """Verify the default timeout is 60s (not 10)"""
    sleep_calls: list = []

    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                swl.main(["prog", "eth0"])

    assert len(sleep_calls) == 60


def test_main_wait_link_timeout_env_var_sets_timeout():
    """Verify WAIT_LINK_TIMEOUT env var is used as the default timeout."""
    sleep_calls: list = []

    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                with patch.dict("os.environ", {"WAIT_LINK_TIMEOUT": "5"}):
                    swl.main(["prog", "eth0"])

    assert len(sleep_calls) == 5


def test_main_cli_timeout_overrides_env_var():
    """Verify CLI timeout argument takes precedence over WAIT_LINK_TIMEOUT env var."""
    sleep_calls: list = []

    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                with patch.dict("os.environ", {"WAIT_LINK_TIMEOUT": "99"}):
                    swl.main(["prog", "eth0", "3"])

    assert len(sleep_calls) == 3


def test_main_invalid_timeout_falls_back_to_60():
    """Verify non-integer timeout falls back to 60s without crashing."""
    sleep_calls: list = []

    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                rc = swl.main(["prog", "eth0", "notanint"])

    assert rc == 0
    assert len(sleep_calls) == 60


def test_main_command_failure_does_not_crash():
    """Verify that subprocess failures are silently swallowed and do not raise."""
    with patch("builtins.open", mock_open(read_data="0")):
        with patch("seer_wait_link.run_best_effort", return_value=run_fail()):
            with patch("time.sleep"):
                rc = swl.main(["prog", "eth0", "1"])

    assert rc == 0


def test_main_carrier_success_enables_promisc_mode():
    """Verify promisc mode is enabled after carrier link is detected."""
    calls: list = []

    def run_mock(cmd: list) -> object:
        calls.append(cmd)
        return run_success()

    with patch("builtins.open", mock_open(read_data="1")):
        with patch("seer_wait_link.run_best_effort", side_effect=run_mock):
            with patch("time.sleep"):
                swl.main(["prog", "eth0"])

    assert any("promisc" in cmd for cmd in calls)


def test_main_lower_up_success_enables_promisc_mode():
    """Verify promisc mode is enabled after LOWER_UP link is detected."""
    calls: list = []

    def run_mock(cmd: list) -> object:
        calls.append(cmd)
        if "show" in cmd:
            return run_success("LOWER_UP")
        return run_success()

    with patch("builtins.open", side_effect=Exception):
        with patch("seer_wait_link.run_best_effort", side_effect=run_mock):
            with patch("time.sleep"):
                swl.main(["prog", "eth0"])

    assert any("promisc" in cmd for cmd in calls)


def test_has_lower_up_uses_ip_dash_d_flag():
    """Verify 'ip -d link show' is used"""
    calls: list = []

    def run_mock(cmd: list) -> object:
        calls.append(cmd)
        return run_success()

    with patch("builtins.open", side_effect=Exception):
        with patch("seer_wait_link.run_best_effort", side_effect=run_mock):
            with patch("time.sleep"):
                swl.main(["prog", "eth0", "1"])

    show_calls = [c for c in calls if "show" in c]
    assert show_calls, "Expected at least one 'ip link show' call."
    assert any("-d" in c for c in show_calls), "Expected -d flag in ip link show call."


def test_main_startup_message_goes_to_stderr_with_timeout(
    capsys: object,
) -> None:
    """Verify the startup 'bringing up and waiting' message is on stderr."""
    with patch("builtins.open", mock_open(read_data="1")):
        with patch("seer_wait_link.run_best_effort", return_value=run_success()):
            with patch("time.sleep"):
                swl.main(["prog", "eth0", "5"])

    captured = capsys.readouterr()
    assert "bringing" in captured.err
    assert "5s" in captured.err
