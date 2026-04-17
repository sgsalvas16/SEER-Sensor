"""Tests for seer_verify_install.py.

Verifies post-install verification logic including config loading, directory
checks, mover detection, service name templating, dummy file behavior, and
cleanup correctness.
"""

import os
import sys
from unittest.mock import patch

sys.path.append(os.path.abspath("Automation/bin"))
import seer_verify_install as svi

# -------------------------
# Helpers
# -------------------------


def mock_config(iface: str = "eth0") -> dict:
    """Return a minimal valid config dict for testing."""
    return {
        "ring_dir": "/ring",
        "dest_dir": "/dest",
        "backlog_dir": "/backlog",
        "json_spool": "/json",
        "buffer_threshold": "4",
        "interface": iface,
    }


def mock_dirs_missing(missing: str):
    """Return an isdir side_effect that returns False only for the given path."""

    def _mock(path: str) -> bool:
        return path != missing

    return _mock


# -------------------------
# Tests
# -------------------------


def test_main_empty_config_returns_exit_2():
    """Verify exit code 2 when config is missing or empty."""
    with patch("seer_verify_install.ensure_root"):
        with patch("seer_verify_install.load_config", return_value={}):
            with patch("builtins.print") as p:
                rc = svi.main(["prog"])

    assert rc == 2
    p.assert_any_call("Verifier: config not found or unreadable")


def test_main_missing_ring_dir_returns_exit_3():
    """Verify exit code 3 when ring_dir does not exist."""
    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", side_effect=mock_dirs_missing("/ring")):
                with patch("builtins.print") as p:
                    rc = svi.main(["prog"])

    assert rc == 3
    p.assert_any_call("Verifier: missing directory /ring")


def test_main_missing_dest_dir_returns_exit_3():
    """Verify exit code 3 when dest_dir does not exist."""
    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", side_effect=mock_dirs_missing("/dest")):
                with patch("builtins.print") as p:
                    rc = svi.main(["prog"])

    assert rc == 3
    p.assert_any_call("Verifier: missing directory /dest")


def test_main_missing_backlog_dir_returns_exit_3():
    """Verify exit code 3 when backlog_dir does not exist."""
    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch(
                "os.path.isdir", side_effect=mock_dirs_missing("/backlog")
            ):
                with patch("builtins.print") as p:
                    rc = svi.main(["prog"])

    assert rc == 3
    p.assert_any_call("Verifier: missing directory /backlog")


def test_main_ring_shrinks_after_mover_returns_passed():
    """Verify exit 0 and PASSED message when ring file count decreases after mover."""
    counts = iter([5, 4])  # before=5 (above threshold=4), after=4

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", side_effect=counts
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            with patch("builtins.print") as p:
                                                rc = svi.main(["prog"])

    assert rc == 0
    p.assert_any_call("Verification PASSED")


def test_main_ring_unchanged_and_no_new_dest_files_returns_failed():
    """Verify exit 3 and FAILED when ring does not shrink and dest/backlog are unchanged."""
    counts = iter([5, 5])  # no change

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", side_effect=counts
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            with patch("builtins.print") as p:
                                                rc = svi.main(["prog"])

    assert rc == 3
    p.assert_any_call(
        "FAIL: no files moved from ring and no new files in dest/backlog"
    )
    p.assert_any_call("Verification FAILED")


def test_main_capture_service_check_uses_templated_unit_name():
    """Verify is-active check uses 'seer-capture@<iface>.service', not bare name."""
    service_checks: list = []

    def systemctl_mock(action: str, service: str) -> int:
        service_checks.append((action, service))
        return 0

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config",
            return_value=mock_config(iface="enp1s0"),
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", return_value=5
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl",
                            side_effect=systemctl_mock,
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            svi.main(["prog"])

    active_checks = [
        svc for action, svc in service_checks if action == "is-active"
    ]
    assert "seer-capture@enp1s0.service" in active_checks
    assert "seer-capture.service" not in active_checks


def test_main_zeek_service_check_uses_templated_unit_name():
    """Verify is-active check uses 'seer-zeek@<iface>.service', not bare name."""
    service_checks: list = []

    def systemctl_mock(action: str, service: str) -> int:
        service_checks.append((action, service))
        return 0

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config",
            return_value=mock_config(iface="enp1s0"),
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", return_value=5
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl",
                            side_effect=systemctl_mock,
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            svi.main(["prog"])

    active_checks = [
        svc for action, svc in service_checks if action == "is-active"
    ]
    assert "seer-zeek@enp1s0.service" in active_checks
    assert "seer-zeek.service" not in active_checks


def test_main_capture_service_inactive_returns_exit_3():
    """Verify exit 3 when capture service is not active."""

    def systemctl_mock(action: str, service: str) -> int:
        if action == "is-active" and "capture" in service:
            return 1
        return 0

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", return_value=5
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl",
                            side_effect=systemctl_mock,
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            with patch("builtins.print") as p:
                                                rc = svi.main(["prog"])

    assert rc == 3
    printed = [str(c) for c in p.call_args_list]
    assert any("FAIL" in s and "capture" in s for s in printed)


def test_main_zeek_service_inactive_returns_exit_3():
    """Verify exit 3 when zeek service is not active."""

    def systemctl_mock(action: str, service: str) -> int:
        if action == "is-active" and "zeek" in service:
            return 1
        return 0

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", return_value=5
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl",
                            side_effect=systemctl_mock,
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            with patch("builtins.print") as p:
                                                rc = svi.main(["prog"])

    assert rc == 3
    printed = [str(c) for c in p.call_args_list]
    assert any("FAIL" in s and "zeek" in s for s in printed)


def test_main_empty_json_spool_is_nonfatal_returns_passed():
    """Verify empty json_spool emits a WARN but does not cause FAILED"""
    counts = iter([5, 4])  # ring shrinks so mover check passes

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", side_effect=counts
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=0,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            with patch("builtins.print") as p:
                                                rc = svi.main(["prog"])

    assert rc == 0
    printed = [str(c) for c in p.call_args_list]
    assert any("WARN" in s and "json_spool" in s for s in printed)
    p.assert_any_call("Verification PASSED")


def test_create_dummy_pcaps_files_use_seer_dummy_prefix():
    """Verify dummy files are named with SEER-DUMMY- prefix"""
    created_names: list = []
    real_open = open

    def open_mock(path, mode="r", *args, **kwargs):
        if "SEER-DUMMY" in str(path):
            created_names.append(os.path.basename(path))
            import io

            return io.BytesIO()
        return real_open(path, mode, *args, **kwargs)

    with patch("builtins.open", side_effect=open_mock):
        with patch("os.makedirs"):
            with patch("os.utime"):
                with patch("seer_verify_install.run"):
                    svi.create_dummy_pcaps("/ring", 3)

    assert len(created_names) == 3
    for name in created_names:
        assert name.startswith("SEER-DUMMY-"), (
            f"Expected SEER-DUMMY- prefix, got: {name}"
        )
        assert name.endswith(".pcap"), f"Expected .pcap extension, got: {name}"


def test_create_dummy_pcaps_mtime_is_backdated_by_at_least_5_seconds():
    """Verify dummy file mtime is backdated so the mover's QUIET_SECS check passes."""
    utime_calls: list = []

    with patch("builtins.open", create=True) as mock_open:
        mock_open.return_value.__enter__ = lambda s: s
        mock_open.return_value.__exit__ = lambda s, *a: False
        mock_open.return_value.write = lambda b: None
        with patch("os.makedirs"):
            with patch(
                "os.utime",
                side_effect=lambda path, times: utime_calls.append(times),
            ):
                with patch("seer_verify_install.run"):
                    svi.create_dummy_pcaps("/ring", 1)

    assert utime_calls, "os.utime should be called to backdate mtime."
    _atime, mtime = utime_calls[0]
    import time

    assert mtime < time.time() - 5, (
        "mtime should be at least 5 seconds in the past."
    )


def test_main_dummy_count_equals_threshold_minus_count_before():
    """Verify exactly (threshold - count_before) dummies are created, no off-by-one."""
    create_calls: list = []

    def create_mock(directory: str, count: int) -> list:
        create_calls.append(count)
        return []

    # count_before=2, threshold=4 → need exactly 2 dummies.
    # Three count_pcap_files calls: initial, after dummies, after mover.
    counts = iter([2, 4, 3])

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", side_effect=counts
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        side_effect=create_mock,
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            svi.main(["prog"])

    assert create_calls == [2], (
        f"Expected 2 dummies created, got {create_calls}"
    )


def test_main_no_dummies_created_when_ring_meets_threshold():
    """Verify create_dummy_pcaps is not called when ring is already at threshold."""
    create_calls: list = []

    def create_mock(directory: str, count: int) -> list:
        create_calls.append(count)
        return []

    counts = iter([4, 3])  # before=4 (at threshold=4), after=3 (mover ran)

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", side_effect=counts
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        side_effect=create_mock,
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps"
                                    ):
                                        with patch("time.sleep"):
                                            svi.main(["prog"])

    assert create_calls == [], (
        f"Expected no dummies created, got {create_calls}"
    )


def test_main_cleanup_called_with_ring_dest_and_backlog_dirs():
    """Verify cleanup_dummy_pcaps receives all three directory paths."""
    cleanup_calls: list = []

    with patch("seer_verify_install.ensure_root"):
        with patch(
            "seer_verify_install.load_config", return_value=mock_config()
        ):
            with patch("os.path.isdir", return_value=True):
                with patch(
                    "seer_verify_install.count_pcap_files", return_value=5
                ):
                    with patch(
                        "seer_verify_install.create_dummy_pcaps",
                        return_value=[],
                    ):
                        with patch(
                            "seer_verify_install.systemctl", return_value=0
                        ):
                            with patch(
                                "seer_verify_install._latest_file",
                                return_value="",
                            ):
                                with patch(
                                    "seer_verify_install._count_log_files",
                                    return_value=1,
                                ):
                                    with patch(
                                        "seer_verify_install.cleanup_dummy_pcaps",
                                        side_effect=lambda r, d, b: (
                                            cleanup_calls.append((r, d, b))
                                        ),
                                    ):
                                        with patch("time.sleep"):
                                            svi.main(["prog"])

    assert cleanup_calls, "cleanup_dummy_pcaps should have been called."
    ring, dest, backlog = cleanup_calls[0]
    assert ring == "/ring"
    assert dest == "/dest"
    assert backlog == "/backlog"
